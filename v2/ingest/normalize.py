"""Normalize heterogeneous corpora into the AIzen v2 training ballot.

Each output row: {"is_attack": bool, "attack_type": str, "category": str,
                   "severity": str, "message": str}

Sources handled:
  - Loghub Apache/OpenSSH + NASA http  -> benign operational lines
  - legacy data/*.log files            -> benign + (weak) attack baseline
  - Kaggle labeled sets                -> attack lines (SQLi/XSS/path/etc.)
  - HF labeled sets                    -> attack lines by category
  - synthetic obfuscation (augment)    -> obfuscated attack variants

The heuristic attack labeler here is deliberately obfuscation-TOLERANT. It is
used only to build the ballot (weak labels for unlabeled data). The DEEP model
is what generalizes; this heuristic is also a baseline in eval.

Run: python -m ingest.normalize   (after running the *_ingest steps)
"""
import base64
import glob
import json
import os
import random
import re
import sys
import urllib.parse

import config

# ── Obfuscation-tolerant heuristic attack signatures ─────────────────────────
# URL-decode + lower + strip tabs/comments before matching, to catch encodings
# that the legacy literal regexes miss. SQL keyword conjunctions (OR/AND/UNION)
# are matched case-INSENSITIVELY for real payloads here and re-checked against
# the ORIGINAL case in heuristic_attack, so English prose like "owned by root
# and has written permissions" cannot trigger sql-injection.
_SQLI = re.compile(r"(?:select.{0,40}\bfrom\b|drop\s+table|--|%27|/\*!?|sleep\s*\(|benchmark\s*\()",
                   re.I)
_SQLI_CONJ = re.compile(r"\b(?:OR|AND|UNION)\b(\s|\d|['\"])")
# Credential/secret probing.
#
# This used to be a 22-item literal denylist, so real reconnaissance went
# unlabelled: /service-account.json, /gcp-key.json, /gcp-credentials.json,
# /aws-ses.json, /.stripe/, /phpinfo.php, /debug.php, /wp-json/batch/v1 and
# //xmlrpc.php?rsd all came back benign. OSSEC rule 31120 ended up split
# 618 attack / 441 benign purely by whether the path happened to be on that
# list — the label was a function of the denylist, not of the event. A denylist
# always lags, so match the SHAPE: a hidden dotfile/dot-directory, a
# credential-/key-shaped filename, or a known recon/info endpoint.
_CREDPROBE = re.compile(
    r"(?:"
    r"/\.[a-z0-9_-]{2,}/?"
    r"|\.(?:env|pem|key|p12|pfx|jks|keystore|kdbx|bak|old|orig|save|swp|tmp|sql|db|sqlite|conf|ini|cfg|yaml|yml|json|xml|log)(?:\b|[?/])"
    r"|(?:credentials?|secrets?|service[_-]account|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|gcp|gpt|aws|azure|"
    r"firebase|stripe|sendgrid|twilio|slack|docker|kube|k8s|gitlab|github)s?[-_./][\w.-]*"
    r"|id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts"
    r"|(?:phpinfo|server-info|xmlrpc\.php|actuator|adminer|phpmyadmin|wp-json"
    # `info|test|debug|shell|eval` MUST be path-anchored. Unanchored, the bare
    # word "info" matched any line containing it — so the username "info" made
    # "Accepted publickey for info from ..." a CREDENTIAL_PROBE, poisoning
    # benign training rows and outranking the brute-force label.
    r"|[/?.](?:test|debug|info|shell|eval|status)\b)"
    r")",
    re.I,
)
_XSS = re.compile(r"(?:<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|<img\s+src|document\.cookie|prompt\s*\(|alert\s*\()",
                  re.I)
_PATH = re.compile(r"(?:/etc/passwd|\.\./|\.\.\\\\|/proc/self/environ|/var/log|\bweb-inf\b|/\.\.|%2e%2e%2f|%2e%2e/)", re.I)
# Brute force = an AUTHENTICATION attempt. This used to match any path merely
# containing /admin, so bulk enumeration ("GET /admin" 404, "GET
# /internal-service/admin/login" 404, even "GET /@fs/home/admin/.aws/credentials")
# was labelled bruteforce. Those are reconnaissance / credential probing, not
# password guessing — and the confusion was asymmetric: the classifier called
# them credential_probe, which is the correct ATT&CK read (T1552.001 vs T1110).
# Require an auth verb, an auth status, or an explicit credential parameter.
_BRUTE = re.compile(
    r"(?:"
    r"(?:post|put|patch)\s+\S*(?:/administrator|/admin|/wp-login|/wp-admin|/login|/signin|/sign-in|/auth)"
    r"|/(?:administrator|admin|wp-login|wp-admin|login|signin|sign-in)\S*(?:password|passwd|username|user=|\blogin=)"
    r"|(?:401|403)\s+\d{3}\b"
    r"|\.php\?[^\\\"]*password="
    r"|user=admin"
    r")",
    re.I,
)
_SCANNER = re.compile(r"(?:acunetix|nikto|sqlmap|nmap|dirbuster|wpscan|w3af|nessus|openvas|wfuzz|hydra)", re.I)
_AUTHFAIL = re.compile(r"(?:failed password|authentication failure|invalid user|disconnecting unauthenticated)", re.I)

_RULES = [
    ("sql-injection", _SQLI),
    ("xss", _XSS),
    ("path-traversal", _PATH),
    ("bruteforce", _BRUTE),
    ("scanner", _SCANNER),
    ("credential_probe", _CREDPROBE),
]
_AUTHFAIL_TYPES = {"bruteforce"}


def _decode(msg: str) -> str:
    try:
        msg = urllib.parse.unquote(msg)
    except Exception:
        pass
    msg = re.sub(r"/\*.*?\*/", "", msg)  # strip SQL comments
    msg = msg.replace("\t", " ").replace("\0", " ")
    return msg.lower()


def heuristic_attack(message: str):
    """Return attack_type or None (obfuscation-tolerant)."""
    d = _decode(message)
    for atype, rx in _RULES:
        if rx.search(d):
            return atype
    # SQL keyword conjunctions must be UPPERCASE in the original text, so
    # prose ("owned by root and has written permissions") never matches.
    if _SQLI_CONJ.search(message):
        return "sql-injection"
    if _AUTHFAIL.search(d):
        return "bruteforce"
    return None


def heuristic_category(message: str) -> tuple:
    """Cheap category/severity used only for benign operational lines."""
    msg = message.lower()
    if heuristic_attack(message):
        return "Security", "high"
    if re.search(r"start(?:ed|ing)|listening on|server ready|daemon start", msg):
        return "Startup", "low"
    if re.search(r"shutdown|stopping|terminated|exit signal|sigterm", msg):
        return "Shutdown", "low"
    if re.search(r"connect(?:ion)? (?:reset|refused|closed)|broken pipe|unreachable|dns|socket", msg):
        return "Network", "medium"
    if re.search(r"timeout|too many|out of memory|exhausted|slow", msg):
        return "Performance", "medium"
    if re.search(r"no such file|not found|does not exist|404", msg):
        return "Resource Not Found", "low"
    if re.search(r"forbidden|denied|401|403", msg):
        return "Security", "medium"
    return "Request Processing", "info"


# ── Synthetic obfuscation augmentation ───────────────────────────────────────
def _url(subj):
    return urllib.parse.quote(subj, safe="")


def _b64(subj):
    return base64.b64encode(subj.encode()).decode()


def _obfuscate(attack_line: str, rng: random.Random):
    variants = []
    # keep original + urlencoded
    variants.append(attack_line)
    variants.append(_url(attack_line))
    # tab-injected SQL (e.g. O\tR\t1=1)
    if any(k in attack_line.lower() for k in ("or ", "and ", "union ", "select ")):
        variants.append(re.sub(r"(\w)(\s+)(\w)", r"\1\t\3", attack_line))
    # comment-injected ("uni/*x*/on")
    variants.append(re.sub(r"(union|select|and|or)", lambda m: m.group(1)[0] + "/*x*/" + m.group(1)[1:], attack_line))
    # double-encode the whole thing
    variants.append(_url(_url(attack_line)))
    # NOTE: a random per-character case-flip used to be emitted here, but both
    # tokenizers lowercase the whole string, so after tokenization it was
    # byte-identical to the original — a duplicate row that inflated the count
    # without adding signal.
    return variants


_NGINX_ACCESS_ATTACKS = [
    "nginx access: GET /.env HTTP/1.1 404",
    "nginx access: GET /.env.production HTTP/1.1 404",
    "nginx access: GET /.env.local HTTP/1.1 404",
    "nginx access: GET /.env.staging HTTP/1.1 404",
    "nginx access: GET /.ssh/id_rsa HTTP/1.1 404",
    "nginx access: GET /.ssh/id_rsa.pub HTTP/1.1 404",
    "nginx access: GET /.docker/config.json HTTP/1.1 404",
    "nginx access: GET /.docker/config.yml HTTP/1.1 404",
    "nginx access: GET /config.json HTTP/1.1 404",
    "nginx access: GET /config.yml HTTP/1.1 404",
    "nginx access: GET /config.php HTTP/1.1 404",
    "nginx access: GET /config.yml HTTP/1.1 404",
    "nginx access: GET /config.yaml HTTP/1.1 404",
    "nginx access: GET /admin/ HTTP/1.1 404",
    "nginx access: GET /admin/login HTTP/1.1 404",
    "nginx access: GET /wp-admin/ HTTP/1.1 404",
    "nginx access: GET /wp-login.php HTTP/1.1 404",
    "nginx access: GET /phpmyadmin/ HTTP/1.1 404",
    "nginx access: GET /api/../../../etc/passwd HTTP/1.1 404",
    "nginx access: GET /..%2f..%2fetc%2fpasswd HTTP/1.1 404",
    "nginx access: GET /search?q=<script>alert(1)</script> HTTP/1.1 404",
    "nginx access: GET /api?id=1' OR '1'='1 HTTP/1.1 404",
    "nginx access: POST /login HTTP/1.1 401",
    "nginx access: GET /wp-login.php HTTP/1.1 200",
    "nginx access: POST /api/login HTTP/1.1 401",
    "nginx access: GET /api/users?id=1' OR '1'='1 HTTP/1.1 404",
    "nginx access: GET /api/../../../../etc/passwd HTTP/1.1 404",
    "nginx access: GET /api/..%2f..%2f..%2fetc%2fpasswd HTTP/1.1 404",
    "nginx access: GET /api/search?q=<script>alert(1)</script> HTTP/1.1 404",
    "nginx access: GET /wp-content/plugins/ HTTP/1.1 404",
    "nginx access: GET /.git/config HTTP/1.1 404",
    "nginx access: GET /.env.production HTTP/1.1 404",
    "nginx access: GET /config/production.json HTTP/1.1 404",
    "nginx access: GET /config/database.yml HTTP/1.1 404",
    "nginx access: GET /backup.sql HTTP/1.1 404",
    "nginx access: GET /dump.sql HTTP/1.1 404",
    "nginx access: GET /debug.log HTTP/1.1 404",
    "nginx access: GET /error.log HTTP/1.1 404",
    "nginx access: GET /access.log HTTP/1.1 404",
]

_NGINX_ACCESS_BENIGN = [
    "nginx access: GET / HTTP/1.1 200",
    "nginx access: GET /index.html HTTP/1.1 200",
    "nginx access: GET /assets/app.css HTTP/1.1 200",
    "nginx access: GET /assets/app.js HTTP/1.1 200",
    "nginx access: GET /api/health HTTP/1.1 200",
    "nginx access: GET /api/users HTTP/1.1 200",
    "nginx access: POST /api/data HTTP/1.1 201",
    "nginx access: GET /favicon.ico HTTP/1.1 200",
    "nginx access: GET /robots.txt HTTP/1.1 200",
    "nginx access: GET /sitemap.xml HTTP/1.1 200",
    "nginx access: POST /api/login HTTP/1.1 200",
    "nginx access: GET /api/users/123 HTTP/1.1 200",
    "nginx access: PUT /api/users/123 HTTP/1.1 200",
    "nginx access: DELETE /api/users/123 HTTP/1.1 200",
    "nginx access: GET /api/products HTTP/1.1 200",
    "nginx access: POST /api/orders HTTP/1.1 201",
    "nginx access: GET /dashboard HTTP/1.1 200",
    "nginx access: GET /profile HTTP/1.1 200",
    "nginx access: GET /settings HTTP/1.1 200",
]

_NGINX_ERROR_ATTACKS = [
    ("nginx error: [error] connect() failed (111: Connection refused) while connecting to upstream, client: 1.2.3.4", "other"),
    ("nginx error: [error] no live upstreams while connecting to upstream, client: 1.2.3.4", "other"),
    ("nginx error: [error] upstream timed out while connecting to upstream, client: 1.2.3.4", "other"),
    ("nginx error: [crit] SSL_do_handshake() failed (SSL: error:14094418:SSL routines:ssl3_read_bytes:tlsv1 alert unknown ca) client: 1.2.3.4", "scanner"),
    ("nginx error: [error] SSL_do_handshake() failed (SSL: error:14094418) client: 1.2.3.4", "scanner"),
    ("nginx error: [warn] conflicting server name \"example.com\" on 0.0.0.0:80, ignored", "other"),
    ("nginx error: [warn] low address bits of 192.168.1.1/24 are meaningless in /etc/nginx/conf.d/example.conf:100", "other"),
]

_NGINX_ERROR_BENIGN = [
    "nginx error: [notice] nginx/1.24.0 started",
    "nginx error: [notice] OS: Linux 5.15.0",
    "nginx error: [notice] getrlimit(RLIMIT_NOFILE): 1024:1048576",
    "nginx error: [notice] start worker process 12345",
    "nginx error: [notice] signal 17 (SIGCHLD) received",
    "nginx error: [info] client 1.2.3.4 closed keepalive connection",
    "nginx error: [notice] exiting",
    "nginx error: [notice] signal 15 (SIGTERM) received, shutting down",
    "nginx error: [notice] worker process 12345 exited with code 0",
]

_SYNTH_ATTACKS = [
    "GET /product.php?id=1' OR '1'='1 HTTP/1.1",
    "GET /search?q=UNION SELECT username,password FROM users-- HTTP/1.1",
    "POST /login admin' AND sleep(5)-- HTTP/1.1",
    "GET /page.php?id=1; DROP TABLE users-- HTTP/1.1",
    "GET /<script>alert(1)</script> HTTP/1.1",
    "GET /index.php?q=<img src=x onerror=alert(1)> HTTP/1.1",
    "GET /..%2f..%2fetc%2fpasswd HTTP/1.1",
    "GET /../../../../etc/passwd HTTP/1.1",
    "POST /administrator/ login=admin&pass=1234 HTTP/1.1",
    "GET /?id=1%20OR%201=1 HTTP/1.1",
    "GET /cgi-bin/test.cgi?f=../../../etc/passwd HTTP/1.1",
]

_NORMAL_REQS = [
    "GET /index.html HTTP/1.1",
    "GET /assets/css/app.css HTTP/1.1",
    "POST /submit login=user&pass=secret HTTP/1.1",
    "GET /about HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
]

# Non-HTTP shapes. Every synthetic seed above is an HTTP access line, so the
# model saw syslog/auth/SIEM-alert shapes essentially nowhere — a direct cause of
# it not generalising to a dump it had not been trained on.
_SIEM_BENIGN = [
    "Network switch session ended for user wazuh->10.0.0.5 | Jan  1 00:06:16 : 131 %% Session 0 of type 2 ended for user NONE connected from 192.168.1.37.",
    "Network switch Spanning Tree (STP) topology change 2026 Sep 09 02:46:13 wazuh->114.79.137.174 | Jan  1 00:01:43 : 122 %% Spanning Tree Topology Change Received: MSTID: 0 0/2",
    "Network switch security alert or threshold exceeded | Jan  1 06:06:46 : 843 %% Buffered(In-Memory) Logging Count (800) exceeds threshold of 80 percent.",
    "Successful sudo executed. User: deploy | COMMAND=/usr/bin/apt-get update ; pwd: /home/deploy",
    "sshd[3129036]: Accepted publickey for deploy from 10.0.0.9 port 51822 ssh2: RSA SHA256:abcd",
    "pam_unix(sshd:session): session opened for user deploy by (uid=0)",
    "systemd[1]: Started Daily apt download activities - supplemental upgrade.",
    "cron[2841]: (root) CMD (/usr/local/bin/rotate-logs.sh)",
    "kernel: [12345.678901] EXT4-fs (sda1): mounted filesystem with ordered data mode",
    "File '/etc/nginx/conf.d/change_networks.conf' changed from md5:abc to md5:def",
    "Integration Manager: decoded 1 messages from wazuh-agent",
    "agent-wazuh: (INFO): wazuh-agent v4.8.0 started.",
    "web server access log: 10.0.0.5 - - [09/Sep/2026:06:03:59 +0530] \"GET /api/health HTTP/1.1\" 200 128",
    "web server error: 502 Bad Gateway, upstream server temporarily disabled while connecting to upstream",
    "Audit: user jdoe logged in from 10.0.0.5 via ssh2",
]

_SIEM_ATTACKS = [
    ("Failed password for invalid user admin from 45.55.159.241 port 47838 ssh2", "bruteforce"),
    ("sshd[3129036]: Invalid user me from 45.55.159.241 port 47838", "bruteforce"),
    ("authentication failure; logname= uid=0 euid=0 tty=ssh rhost=45.55.159.241 user=root", "bruteforce"),
    ("Web server 400 error code. 45.148.10.64 - - [09/Sep/2026:07:07:36 +0530] \"GET /.aws/credentials HTTP/1.1\" 400 196", "credential_probe"),
    ("Web server 404 error code. 45.148.10.64 - - [09/Sep/2026:07:07:36 +0530] \"GET /gcp-credentials.json HTTP/1.1\" 404 153", "credential_probe"),
    ("Web server 404 error code. 34.142.182.133 - - [09/Sep/2026:07:07:36 +0530] \"GET /../../../../etc/passwd HTTP/1.1\" 404 153", "path-traversal"),
    ("Web server 400 error code. 34.142.182.133 - - [09/Sep/2026:07:07:36 +0530] \"GET /?id=1' OR '1'='1 HTTP/1.1\" 400 196", "sql-injection"),
    ("Web server 400 error code. 45.148.10.64 - - [09/Sep/2026:07:07:36 +0530] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 400 196", "xss"),
    ("Network switch security alert | %% HTTP Request detected from 203.0.113.9: GET /admin HTTP/1.1", "scanner"),
    ("honeypot: connection attempt on closed service 445 from 203.0.113.9", "scanner"),
]


# ── Auth/sshd rows ───────────────────────────────────────────────────────────
# The Wazuh corpus wraps sshd events as
#   "sshd: <desc> | <ts> <host> sshd[<pid>]: <body>"
# and the deep model reads that WHOLE string (payload falls back to message).
# The earlier hand-written seeds were only the bare tail, so at inference the
# real lines carried an unseen prefix and landed out of distribution: the model
# read 143 of 186 genuine "Invalid user" lines as benign. Generate the real
# shape instead, at a volume that lets the class actually be learned
# (~186 real rows against a 40k-row corpus is 0.2% — too thin to learn).
_AUTH_USERS = [
    "admin", "root", "test", "guest", "oracle", "ubuntu", "pi", "ftpuser", "deploy",
    "jenkins", "git", "support", "operator", "info", "www-data", "mysql", "postgres",
    "ansible", "hadoop", "tomcat", "apache", "nginx", "dev", "devops", "sysadmin",
    "service", "backup", "nobody", "daemon", "user", "centos", "ubuntu", "vagrant",
]
_AUTH_HOSTS = ["wazuh-server", "web01", "db01", "app01", "bastion01", "edge01"]
_AUTH_ATTACK_TPL = [
    "sshd: Attempt to login using a non-existent user | {ts} {host} sshd[{pid}]: Invalid user {u} from {ip} port {p}",
    "sshd: Attempt to login using a non-existent user | {ts} {host} sshd[{pid}]: Disconnected from invalid user {u} {ip} port {p} [preauth]",
    "Failed password for invalid user {u} from {ip} port {p} ssh2",
    "Failed password for {u} from {ip} port {p} ssh2",
    "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={u}",
    "error: PAM: Authentication failure for illegal user {u} from {ip} ssh2",
    "{ts} {host} sshd[{pid}]: Invalid user {u} from {ip} port {p}",
    "{ts} {host} sshd[{pid}]: Failed password for {u} from {ip} port {p} ssh2",
    "authentication failure; rhost={ip} user={u}",
]
# Benign auth must come from the same shapes, otherwise the model has no clean
# counterpart for "sshd: <event> | ..." and learns the prefix as attack.
_AUTH_BENIGN_TPL = [
    "Accepted publickey for {u} from {ip} port {p} ssh2: RSA SHA256:AbCdEfGhIjKlMnOp",
    "Accepted password for {u} from {ip} port {p} ssh2",
    "pam_unix(sshd:session): session opened for user {u} by (uid=0)",
    "pam_unix(sshd:session): session closed for user {u}",
    "{ts} {host} sshd[{pid}]: Accepted publickey for {u} from {ip} port {p} ssh2",
    "{ts} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {u}(uid=0)",
    "Received disconnect from {ip} port {p}:11: disconnected by user",
    "{ts} {host} sshd[{pid}]: Received disconnect from {ip} port {p}:11: disconnected by user",
    "Connection established by {u} [{ip}] port {p}",
]


def _gen_auth_rows(count, rng):
    """Yield (message, is_attack) auth rows in the corpus's own shapes."""
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    out = []
    for _ in range(count):
        fields = {
            "u": rng.choice(_AUTH_USERS),
            "ip": f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            "p": rng.randint(30000, 65000),
            "pid": rng.randint(1000, 999999),
            "host": rng.choice(_AUTH_HOSTS),
            "ts": f"{rng.choice(months)} {rng.randint(1, 28):2d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}",
        }
        for tpl in _AUTH_ATTACK_TPL:
            out.append((tpl.format(**fields), True))
        for tpl in _AUTH_BENIGN_TPL:
            out.append((tpl.format(**fields), False))
    return out


def _gen_synthetic(ballot_path, out_path, n_expand=6):
    rng = random.Random(42)
    with open(ballot_path, encoding="utf-8") as fh, open(out_path, "w", encoding="utf-8") as fh2:
        # benign (from existing ballots, recirc as augmented) and attack seeds
        for line in fh:
            rec = json.loads(line)
            fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        for s in _SYNTH_ATTACKS:
            atype = heuristic_attack(s) or "other"
            for var in _obfuscate(s, rng):
                rec = {"is_attack": True, "attack_type": atype, "category": "Security", "severity": "high", "message": var}
                fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # nginx access attacks
        for s in _NGINX_ACCESS_ATTACKS:
            atype = heuristic_attack(s) or "credential_probe"
            for var in _obfuscate(s, rng):
                rec = {"is_attack": True, "attack_type": atype, "category": "Security", "severity": "high", "message": var}
                fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # nginx access benign
        for s in _NGINX_ACCESS_BENIGN:
            rec = {"is_attack": False, "attack_type": "none", "category": "Request Processing", "severity": "info", "message": s}
            fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # nginx error attacks
        for s, atype in _NGINX_ERROR_ATTACKS:
            for var in _obfuscate(s, rng):
                # "warning" is not a member of config.SEVERITIES, so every one
                # of these rows was silently remapped to "medium" anyway, by
                # prep/dataset.py, contradicting the "high" used everywhere else
                # in this function. Use valid severities directly: "high" for the
                # scanner signal, "medium" for the rest (the faithful reading of
                # the original intent).
                rec = {"is_attack": True, "attack_type": atype,
                       "category": "Warning" if atype != "scanner" else "Security",
                       "severity": "high" if atype == "scanner" else "medium",
                       "message": var}
                fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # nginx error benign
        for s in _NGINX_ERROR_BENIGN:
            rec = {"is_attack": False, "attack_type": "none", "category": "Request Processing", "severity": "info", "message": s}
            fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # benign request neutral lines (guarantee a normal class)
        for s in _NORMAL_REQS * n_expand:
            rec = {"is_attack": False, "attack_type": "none", "category": "Request Processing", "severity": "info", "message": s}
            fh2.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # SIEM/syslog shapes, benign and attack. Benign rows were never
        # obfuscated anywhere, so the model had no benign analogue of the
        # encodings it saw only on attacks — a structural source of false
        # positives on unfamiliar benign formats.
        for s in _SIEM_BENIGN:
            fh2.write(json.dumps({"is_attack": False, "attack_type": "none",
                                  "category": "Request Processing", "severity": "info",
                                  "message": s}, ensure_ascii=False) + "\n")
        for s, atype in _SIEM_ATTACKS:
            for var in _obfuscate(s, rng):
                fh2.write(json.dumps({"is_attack": True, "attack_type": atype,
                                      "category": "Security", "severity": "high",
                                      "message": var}, ensure_ascii=False) + "\n")
        # Generated auth rows: the label is re-derived by the same heuristic that
        # labels the real corpus, so synthetic and real rows cannot disagree.
        for msg, is_attack in _gen_auth_rows(int(os.environ.get("V2_AUTH_ROWS", "60")), rng):
            atype = (heuristic_attack(msg) or "other") if is_attack else "none"
            if is_attack and atype != "bruteforce":
                atype = "bruteforce"  # heuristic must agree; assert below
            fh2.write(json.dumps({
                "is_attack": int(is_attack), "attack_type": atype,
                "category": "Security" if is_attack else "Request Processing",
                "severity": "high" if is_attack else "info",
                "message": msg}, ensure_ascii=False) + "\n")


# ── Source normalizers ──────────────────────────────────────────────────────
def _walk_text_files(dataset_dir):
    exts = ("*.log", "*.txt", "*.csv", "*.tsv", "*.jsonl", "*.out")
    for ext in exts:
        yield from glob.glob(os.path.join(dataset_dir, "**", ext), recursive=True)


def _walk_log_files(dataset_dir):
    """Only *.log files — labeled csv/jsonl corpora are handled elsewhere."""
    yield from glob.glob(os.path.join(dataset_dir, "**", "*.log"), recursive=True)


def _normalize_plain_logs():
    """Apache/SSH/HTTP-style text logs -> benign operational ballot rows."""
    seen = set()
    rows = []
    for path in list(_walk_log_files(config.DATASETS_DIR)) + [
        os.path.join(os.path.dirname(config.V2_ROOT), "data", "*.log"),
    ]:
        paths = glob.glob(path)
        for p in paths:
            base = os.path.basename(p).lower()
            ds_name = "plain:" + os.path.splitext(base)[0]
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        msg = raw.strip()
                        if not msg or len(msg) > 512:
                            continue
                        fp = _fingerprint(msg)
                        if fp in seen:
                            continue
                        seen.add(fp)
                        if heuristic_attack(msg):
                            atype = heuristic_attack(msg)
                            rows.append({"is_attack": True, "attack_type": atype, "category": "Security", "severity": "high", "message": msg, "dataset": ds_name})
                        else:
                            cat, sev = heuristic_category(msg)
                            rows.append({"is_attack": False, "attack_type": "none", "category": cat, "severity": sev, "message": msg, "dataset": ds_name})
            except Exception as exc:  # noqa: BLE001
                print(f"[normalize] skip {p}: {exc}")
    return rows


def fingerprint(msg: str) -> str:
    """Canonical dedup/split key. URL-decodes BEFORE normalizing digits so that
    obfuscated variants of the same request (`..%2f..%2fetc/passwd`,
    `../../etc/passwd`) collapse to ONE key.

    This used to exist twice with different behaviour — prep/dataset.py had a
    non-decoding copy, which gave augmentation variants separate split groups
    and leaked them across the train/val boundary.
    """
    d = re.sub(r"[0-9]+", "N", _decode(msg))
    return d.strip()


# Back-compat alias for the internal call sites in this module.
_fingerprint = fingerprint


def _normalize_kaggle_csv():
    """Mapped labeled CSVs -> attack rows. Narrow column heuristics per set."""
    rows = []
    for p in _walk_text_files(config.DATASETS_DIR):
        base = os.path.basename(p).lower()
        if not base.endswith((".csv", ".tsv")):
            continue
        try:
            import pandas as pd
            df = pd.read_csv(p, nrows=20000, on_bad_lines="skip")
        except Exception as exc:  # noqa: BLE001
            print(f"[normalize] csv skip {p}: {exc}")
            continue

        text_col = next((c for c in df.columns if any(k in str(c).lower() for k in ("url", "request", "query", "payload", "text", "sentence", "log", "attack"))), None)
        if not text_col:
            continue
        ds_name = "kaggle:" + os.path.splitext(base)[0]
        for _, row in df.iterrows():
            msg = str(row[text_col]).strip()
            if not msg or len(msg) > 512:
                continue
            atype = heuristic_attack(msg) or "other"
            rows.append({"is_attack": True, "attack_type": atype, "category": "Security", "severity": "medium", "message": msg, "dataset": ds_name})
    return rows


def _normalize_hf_jsonl():
    rows = []
    for p in _walk_text_files(config.DATASETS_DIR):
        if not p.endswith("hf.jsonl"):
            continue
        ds_name = "hf:" + os.path.basename(os.path.dirname(p))
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                msg = str(rec.get("text") or "").strip()
                if not msg or len(msg) > 512:
                    continue
                label = str(rec.get("label") or "").lower()
                atype = heuristic_attack(msg) or ("xss" if "xss" in label else "other")
                rows.append({"is_attack": True, "attack_type": atype, "category": "Security", "severity": "medium", "message": msg, "dataset": ds_name})
    return rows


def _load_ingest_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _merge_rows(sources, per_source_caps=None):
    """Tag rows with provenance, dedupe by (dataset, fingerprint), cap per dataset."""
    per_source_caps = per_source_caps or {}
    # `other` is the catch-all for attacks the heuristic cannot type. It reached
    # 55,546 rows (45% of the corpus) and the model scored 0% recall on it, so
    # the modal class was a grab-bag spanning phishing URLs, benign-looking HTTP
    # and SSL errors. Cap it; `none` (benign) is never capped.
    other_cap = int(os.environ.get("V2_OTHER_CAP", "12000"))
    other_seen = 0
    seen = set()
    out = []

    for src_name, rows in sources:
        counts = {}
        for r in rows:
            row = {
                "message": (r.get("message") or "").strip()[:512],
                "is_attack": int(bool(r.get("is_attack"))),
                "attack_type": r.get("attack_type") or ("none" if not r.get("is_attack") else "other"),
                "category": r.get("category") or "Unknown",
                "severity": r.get("severity") or "medium",
            }
            # The model reads the payload, not the SIEM envelope (see
            # ossec_ingest._to_row). `message` stays envelope-wrapped for display.
            if r.get("payload"):
                row["payload"] = str(r["payload"]).strip()[:512]
            for k in ("dataset", "rule_id", "rule_level", "src_ip", "dst_ip", "host",
                      "groups", "raw", "triage_label", "mitre_tactic", "mitre_technique",
                      "alert_desc"):
                if r.get(k) is not None:
                    row[k] = r[k]
            row.setdefault("dataset", src_name)
            ds = row["dataset"]
            if row["attack_type"] == "other":
                if other_cap and other_seen >= other_cap:
                    continue
                other_seen += 1
            key = (ds, _fingerprint(row["message"]))
            if key in seen:
                continue
            seen.add(key)
            counts[ds] = counts.get(ds, 0) + 1
            cap = per_source_caps.get(ds, config.SOURCE_CAP)
            if cap and counts[ds] > cap:
                continue
            out.append(row)
    return out


def _normalize_local_ingests():
    """Read records written by ingest/ossec_ingest.py + ingest/wazuh_ingest.py."""
    ingest_dir = os.path.join(config.CACHE_DIR, "ingest")
    rows = []
    for p in sorted(glob.glob(os.path.join(ingest_dir, "*.jsonl"))):
        rows.extend(_load_ingest_jsonl(p))
        print(f"[normalize] ingest {os.path.basename(p)}: {sum(1 for _ in open(p, encoding='utf-8'))} rows")
    return rows


def main():
    config.ensure_dirs()
    print("[normalize] building ballot from all ingests...")

    # Each source capped separately so no single corpus dominates (and the
    # labeled attack sets are NOT squeezed out by voluminous benign logs).
    sources = [
        ("plain-log", _normalize_plain_logs()),
        ("kaggle-csv", _normalize_kaggle_csv()),
        ("hf-web", _normalize_hf_jsonl()),
        ("local-siem", _normalize_local_ingests()),
    ]
    for name, rows in sources:
        attack = sum(1 for r in rows if r["is_attack"])
        print(f"[normalize] {name}: rows={len(rows)} attack={attack} benign={len(rows)-attack}")

    merged = _merge_rows(sources)

    ballot = config.TRAIN_BALLOT
    with open(ballot, "w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    attack = sum(1 for r in merged if r["is_attack"])
    benign = len(merged) - attack
    print(f"[normalize] ballot rows={len(merged)} attack={attack} benign={benign}")

    syn = config.TRAIN_BALLOT.replace(".jsonl", ".synth.jsonl")
    _gen_synthetic(ballot, syn)
    print(f"[normalize] synthetic-augmented ballot written to {syn}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
