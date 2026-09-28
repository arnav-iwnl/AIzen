"""Parse local OSSEC/Wazuh alert logs into labeled v2 records.

OSSEC alert file format has blocks:
    ** Alert <unixtime>: - group1,group2,...
    <ts> (<hostname>) <agent>-><location>
    Rule: <id> (level <lvl>) -> '<description>'
    Src IP: <ip>
    ...raw log lines...

Labels are DERIVED, never fabricated:
  - attacks require evidence: alert group tags (`attack`, `web_attack`,
    `recon`, `web_scan`, `ids`), known CVE rules (23503..23506), or high
    severity with a security group.
  - everything else is benign with category/severity from rule level + group.
Attack subtype uses the same obfuscation-tolerant heuristic as normalize.py.

Provenance (dataset, rule_id, rule_level, src_ip, hostname, groups, raw) is
kept on every record so training can attribute labels and split leak-free.

Run: python -m ingest.ossec_ingest
"""
import glob
import os
import re
import sys

import config
from ingest.common import mkdir

ALERT = re.compile(r"^\*\* Alert (?P<ts>\S+): - (?P<groups>[^*]*)$")
HEADER = re.compile(r"^(?P<ts>\d{4} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}) \((?P<host>[^)]+)\) (?P<agent>[^-]+)->(?P<location>.+)$")
RULE = re.compile(r"^Rule: (?P<rule_id>\d+) \(level (?P<level>\d+)\) -> '(?P<desc>[^']*)'")
SRCIP = re.compile(r"^Src IP:\s*(?P<ip>\S+)")
DSTIP = re.compile(r"^Dst IP:\s*(?P<ip>\S+)")

# Rule IDs known to mean attack (OSSEC/Wazuh default rule set saw in the log).
_CVE_RULES = {"23503", "23504", "23505", "23506"}          # CVE-... affects ...
_ATTACK_GROUPS = {"attack", "web_attack", "recon", "web_scan", "ids"}


def _level_to_sev(level):
    if level >= 10:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _group_category(groups):
    """Map OSSEC alert groups to the ballot category for benign rows."""
    g = set(groups)
    if g & {"performance_metric"}:
        return "Performance"
    if g & {"network_switch", "network"} or any("network" in x for x in g):
        return "Network"
    if g & {"syscheck", "registry", "windows", "rootcheck"}:
        return "Configuration"
    if g & {"authentication_success", "authentication_failed", "authentication"}:
        return "Security"
    if g & {"nginx", "web", "accesslog", "apache"}:
        return "Request Processing"
    if g & {"syslog"}:
        return "Warning"
    return "Unknown"


def _attack_type_from_evidence(message, groups):
    """Subtype for rows already deemed attacks."""
    from ingest.normalize import heuristic_attack
    at = heuristic_attack(message) or "other"
    if at != "other":
        return at
    g = set(groups)
    # no payload signature -> infer from alert group intent (kept coarse)
    if g & {"recon", "web_scan"}:
        return "scanner"
    if g & {"web_attack", "attack"}:
        return "other"
    return "other"


def _is_attack_block(groups, rule_id, level, message):
    g = set(groups)
    if g & _ATTACK_GROUPS:
        return True
    if rule_id in _CVE_RULES:
        return True
    # security-adjacent group and a real payload/credential signature
    from ingest.normalize import heuristic_attack
    if g & {"web", "accesslog", "authentication_failed"} and level >= 5 and heuristic_attack(message):
        return True
    return False


def parse_alerts(path):
    """Yield dicts for every ** Alert block in an OSSEC log file."""
    blocks = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()

    cur = None
    for line in lines:
        m = ALERT.match(line)
        if m:
            if cur:
                blocks.append(cur)
            cur = {"ts": m.group("ts"), "groups": [x.strip() for x in m.group("groups").split(",") if x.strip()],
                   "rule_id": None, "level": None, "desc": "", "src_ip": None, "dst_ip": None,
                   "host": None, "agent": None, "location": None, "body": []}
            continue
        if cur is None:
            continue
        m = RULE.match(line)
        if m:
            cur["rule_id"] = m.group("rule_id")
            cur["level"] = int(m.group("level"))
            cur["desc"] = m.group("desc")
            continue
        m = HEADER.match(line)
        if m and cur["host"] is None:
            cur["host"] = m.group("host")
            cur["agent"] = m.group("agent").strip()
            cur["location"] = m.group("location").strip()
            continue
        m = SRCIP.match(line)
        if m:
            cur["src_ip"] = m.group("ip")
            continue
        m = DSTIP.match(line)
        if m:
            cur["dst_ip"] = m.group("ip")
            continue
        if cur["body"] or line.strip():
            cur["body"].append(line.rstrip())
    if cur:
        blocks.append(cur)
    return blocks


def _to_row(b, dataset_name):
    groups = b["groups"]
    level = b["level"] or 0
    rule_id = b["rule_id"] or "?"
    body = " | ".join(x.strip() for x in b["body"] if x.strip())[:512]
    payload = body
    message = f"{b['desc']} {body}".strip()[:512] if body else b["desc"]
    if not message:
        return None

    is_attack = _is_attack_block(groups, rule_id, level, payload or message)
    if is_attack:
        attack_type = _attack_type_from_evidence(payload or message, groups)
        category = "Security"
        severity = "critical" if level >= 10 else ("high" if level >= 7 else "medium")
    else:
        attack_type = "none"
        category = _group_category(groups)
        severity = _level_to_sev(level)

    return {
        # `message` keeps the SIEM envelope ("<alert desc> <body>") because that
        # is what the UI and RCA render. `payload` is the log evidence alone.
        #
        # The model must read `payload`, not `message`. With the envelope
        # included, 1792 of 2123 false positives were a single benign Cisco
        # switch syslog scored as `bruteforce`, while a bare "Failed password for
        # invalid user" fell below threshold — the network had learned the alert
        # wrapper instead of the payload, which is precisely the failure mode for
        # a log format the model has never seen.
        "message": message,
        "payload": payload or message,
        "alert_desc": b["desc"],
        "is_attack": int(is_attack),
        "attack_type": attack_type,
        "category": category,
        "severity": severity,
        # provenance
        "dataset": dataset_name,
        "rule_id": rule_id,
        "rule_level": level,
        "src_ip": b["src_ip"],
        "dst_ip": b["dst_ip"],
        "host": b["host"],
        "groups": groups,
        "raw": "\n".join(b["body"]),
        "timestamp": b["ts"],
    }


def main():
    config.ensure_dirs()
    outdir = mkdir(os.path.join(config.CACHE_DIR, "ingest"))
    out_path = os.path.join(outdir, "ossec_alerts.jsonl")
    patterns = [
        os.path.join(config.DATASETS_DIR, "ossec-local", "*.log*"),
        os.path.join(config.V2_ROOT, "data", "ossec*.txt"),
        os.path.join(config.V2_ROOT, "data", "*ossec*"),
    ]
    paths = []
    for pat in patterns:
        paths += glob.glob(pat)
    paths = sorted(set(paths))
    if not paths:
        print("[ossec] no local OSSEC files found")
        return 0

    n = 0
    with open(out_path, "w", encoding="utf-8") as fh:
        for p in paths:
            for b in parse_alerts(p):
                row = _to_row(b, os.path.splitext(os.path.basename(p))[0])
                if not row:
                    continue
                fh.write(__import__("json").dumps(row, ensure_ascii=False) + "\n")
                n += 1
    print(f"[ossec] {n} labeled OSSEC records -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())