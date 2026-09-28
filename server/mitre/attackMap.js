/**
 * attackMap — the single MITRE ATT&CK + system-error vocabulary for AIzen.
 *
 * One map covers BOTH detectors, because both are normalized to the same family
 * key space by `famKey()`:
 *   - rule engine  : securityTypes = CREDENTIAL_PROBE, SQL_INJECTION, AUTH_FAILURE, ...
 *   - v2 deep model: attack_type  = credential_probe, sql-injection, bruteforce, ...
 * `ALIASES` bridges the v2 label spelling to the rule/playbook family name
 * (bruteforce -> ADMIN_BRUTE_FORCE, xss -> XSS_PROBE, scanner -> SCANNER_SIGNATURE).
 *
 * Remediation steps deliberately live in localRootCauseService.PLAYBOOKS, not
 * here — the playbook text is the recovery guidance and duplicating it per
 * technique would just be two copies that drift.
 *
 * Non-attack failures (nginx upstream/SSL/config, network, resource pressure)
 * are NOT ATT&CK techniques and must not be labelled as such — they get their
 * own SYS-* catalog below.
 */

/** v2 label / rule type -> canonical family key. */
const ALIASES = {
  BRUTEFORCE: 'ADMIN_BRUTE_FORCE',
  XSS: 'XSS_PROBE',
  SCANNER: 'SCANNER_SIGNATURE',
};

/** Family -> ATT&CK technique. Only entries with a defensible technique are listed. */
const TECHNIQUES = {
  CREDENTIAL_PROBE: {
    id: 'T1552.001',
    name: 'Unsecured Credentials: Credentials In Files',
    tactic: 'Credential Access',
    rationale: 'Requests for cloud credential files, .env files, key material and auth config paths.',
  },
  PATH_TRAVERSAL: {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    rationale: 'Traversal sequences and probes for sensitive filesystem paths outside the web root.',
  },
  SQL_INJECTION: {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    rationale: 'Injection metacharacters aimed at a public endpoint, attempting to manipulate its backend query.',
  },
  ADMIN_BRUTE_FORCE: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    subtechnique: 'T1110.001 Password Guessing',
    rationale: 'Repeated authentication attempts against admin/login endpoints.',
  },
  XSS_PROBE: {
    id: 'T1059.007',
    name: 'Command and Scripting Interpreter: JavaScript',
    tactic: 'Execution',
    rationale: 'Script/event-handler payloads injected into a request parameter, seeking browser-side execution.',
  },
  SCANNER_SIGNATURE: {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    rationale: 'Known scanner tooling probing the service to enumerate it.',
  },
  DIRECTORY_FORBIDDEN: {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    rationale: 'Directory enumeration attempts blocked by server rules.',
  },
  AUTH_FAILURE: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    rationale: 'Failed authentication attempts (rule-only signal; the deep model reports these as bruteforce).',
  },
  // Runtime-only: synthesized by detectorService when one source IP racks up
  // nginx upstream/SSL failures. That IS active scanning, not a system fault.
  NGINX_UPSTREAM_SCAN_SUSPECTED: {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    rationale: 'A single source drove many upstream failures — consistent with probing, not upstream instability.',
  },
  NGINX_SSL_SCAN_SUSPECTED: {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    rationale: 'A single source drove repeated TLS handshake failures — consistent with service enumeration.',
  },
  // Catch-all class from the deep model: no single technique is defensible.
  OTHER: null,
};

/** Non-attack failures. Keyed by nginx signal name OR by classification category. */
const SYSTEM_ERRORS = {
  NGINX_UPSTREAM_FAILURE: {
    id: 'SYS-NGINX-UPSTREAM-DOWN',
    name: 'Upstream service unreachable (502/503/504)',
    meaning: 'The proxy could not reach or connect to the backend upstream.',
    fix: 'Check upstream health, DNS and the connection pool; confirm the backend is listening and not restarting.',
  },
  NGINX_UPSTREAM_TIMEOUT: {
    id: 'SYS-NGINX-UPSTREAM-TIMEOUT',
    name: 'Upstream response timed out',
    meaning: 'The backend accepted the connection but did not answer within proxy_read_timeout.',
    fix: 'Profile slow queries/handlers, then align proxy_read_timeout with real p99 latency or fix the slow path.',
  },
  NGINX_SSL_HANDSHAKE_FAILURE: {
    id: 'SYS-TLS-HANDSHAKE',
    name: 'TLS handshake failed',
    meaning: 'Certificate/protocol negotiation failed between client and server.',
    fix: 'Verify the certificate chain, expiry, SNI matching and the enabled protocol/cipher set.',
  },
  NGINX_CONFIG_WARNING: {
    id: 'SYS-CONFIG-DRIFT',
    name: 'Web server configuration warning',
    meaning: 'The server started with a suspect or conflicting directive.',
    fix: 'Reconcile the flagged directives against the intended config; run `nginx -t` after each change.',
  },
  NGINX_CRITICAL_ERROR: {
    id: 'SYS-WORKER-CRITICAL',
    name: 'Worker/process critical condition',
    meaning: 'A worker hit a critical condition (crash, restart, resource ceiling).',
    fix: 'Inspect worker logs around the event, then check memory/cpu limits and restart counts.',
  },
  'Backend Communication': {
    id: 'SYS-BACKEND-COMM',
    name: 'Backend communication failure',
    meaning: 'Worker/proxy connections to the backend are failing.',
    fix: 'Verify upstream availability, connection limits and retry/timeout configuration.',
  },
  Network: {
    id: 'SYS-NETWORK-PATH',
    name: 'Network path / DNS failure',
    meaning: 'Connectivity between tiers is unstable or name resolution is failing.',
    fix: 'Check reachability across tiers, DNS TTL/cache and recent firewall changes.',
  },
  Performance: {
    id: 'SYS-RESOURCE-EXHAUSTION',
    name: 'Resource exhaustion (timeout / pressure)',
    meaning: 'Timeouts and saturation dominate, pointing at under-provisioning or runaway workers.',
    fix: 'Check memory/cpu saturation and swap, review worker/thread pool limits, correlate with deploys.',
  },
  'Service Instability': {
    id: 'SYS-SERVICE-INSTABILITY',
    name: 'Service instability (restart/crash loop)',
    meaning: 'Repeated worker failures indicate a cascading failure or crash loop.',
    fix: 'Inspect the crash/restart sequence and the last config or deploy that preceded it.',
  },
  'Resource Not Found': {
    id: 'SYS-ROUTE-MISSING',
    name: 'Missing route or asset (404/400 volume)',
    meaning: 'Requests are hitting endpoints that do not exist, at volume.',
    fix: 'Separate broken links from attacker enumeration, then rate-limit or challenge 404-heavy sources.',
  },
  Configuration: {
    id: 'SYS-CONFIG-INTEGRITY',
    name: 'Configuration / file-integrity anomaly',
    meaning: 'Host-based integrity or config anomalies were flagged against system files.',
    fix: 'Diff the flagged files against a trusted baseline and restore anything that drifted.',
  },
  Startup: {
    id: 'SYS-STARTUP',
    name: 'Startup / initialization failure',
    meaning: 'The service failed to initialize cleanly.',
    fix: 'Compare the startup flags and config against the last known-good deployment.',
  },
};

/**
 * ATT&CK techniques the v2 head can now emit directly as a label (Stage A
 * uncap: the attack head learns real technique ids from the corpus, so a
 * prediction may already BE a technique id rather than a legacy attack name).
 * Only techniques the model is actually trained on are listed; anything else
 * degrades to an id-only entry with no invented name.
 */
const BY_ID = {
  T1110: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  T1021: { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
  'T1021.002': { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
  T1041: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  T1068: { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  // Annotated on the corpus but only on non-attack rows today — reachable once
  // the technique head is decoupled from is_attack.
  T1583: { id: 'T1583', name: 'Acquire Infrastructure', tactic: 'Resource Development' },
  T1082: { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  T1059: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  T1053: { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence' },
  T1562: { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion' },
  T1071: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  T1005: { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
};

/** Normalize a rule securityType or a v2 attack_type to its family key. */
const famKey = (type) => {
  const raw = String(type || '').replace(/^v2:/, '').replace(/-/g, '_').toUpperCase();
  return ALIASES[raw] || raw;
};

/** ATT&CK technique for a rule securityType or v2 attack_type (null when unmappable). */
function techniqueFor(type) {
  const key = famKey(type); // a technique id survives normalization unchanged
  if (TECHNIQUES[key] !== undefined) return TECHNIQUES[key];
  if (BY_ID[key]) return BY_ID[key];
  if (/^T\d{4}(\.\d{3})?$/.test(key)) {
    // Trained on but absent from the catalog: report the id, never invent a name.
    return { id: key, name: key, tactic: 'Unmapped', rationale: 'Emitted by the deep classifier; no local catalog entry.' };
  }
  return null;
}

/** ATT&CK technique for an already-normalized family key. */
function techniqueForFamily(family) {
  return TECHNIQUES[family] !== undefined ? TECHNIQUES[family] : BY_ID[family] || null;
}

/** Deduplicated technique list for a set of signal types, ordered by first seen. */
function techniquesFor(types = []) {
  const out = [];
  const seen = new Set();
  for (const t of types) {
    const tech = techniqueFor(t);
    if (!tech || seen.has(tech.id)) continue;
    seen.add(tech.id);
    out.push(tech);
  }
  return out;
}

/** System-error entry for a signal name (NGINX_*) or a classification category. */
function systemErrorFor(nameOrCategory) {
  return SYSTEM_ERRORS[nameOrCategory] || null;
}

/** Canonical ATT&CK page for a technique id (T1110.001 -> .../T1110/001/). */
function mitreUrl(id) {
  if (!id) return null;
  return `https://attack.mitre.org/techniques/${String(id).replace('.', '/')}/`;
}

module.exports = {
  ALIASES,
  TECHNIQUES,
  BY_ID,
  SYSTEM_ERRORS,
  famKey,
  techniqueFor,
  techniqueForFamily,
  techniquesFor,
  systemErrorFor,
  mitreUrl,
};
