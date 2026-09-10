const logStore = require('../store/logStore');
const contextSelector = require('./contextSelector');
const rules = require('../rules/logRules');
const v2Detections = require('../ml/v2Detections');
const { formatTimelineTimestamp } = require('../utils/helpers');
const logger = require('../utils/logger');

/** Attack-family -> remediation playbook. `steps` are concrete, actionable. */
const PLAYBOOKS = {
  CREDENTIAL_PROBE: {
    action: 'Remove exposed credentials & harden auth paths',
    priority: 'high',
    summary: 'Attackers probed for stored credentials and auth tokens.',
    steps: [
      'Deny the listed secret paths (auth.json, *.credentials, .env, .ssh, accessTokens) at the reverse-proxy/static layer.',
      'Rotate every credential that lives in an exposed file: cloud access tokens, API keys, SSH keys.',
      'Move secrets out of the web tree into a secrets manager or environment injector.',
      'Add alerting on auth/token endpoint request spikes (per source IP).',
    ],
  },
  PATH_TRAVERSAL: {
    action: 'Stop file-traversal leaks and reject ".." requests',
    priority: 'high',
    summary: 'Requests attempted to escape the web root and read system or cloud files.',
    steps: [
      'Reject requests containing ".." or targeting /.env, /etc/*, /proc/* at the edge (WAF / nginx deny).',
      'Serve static content with path normalization that resolves ".." and forbids escapes from the web root.',
      'Validate /download?file= and same-path handlers against a whitelisted base directory.',
      'Remove cloud credential files (.azure/.credentials, .config/gcloud) from served locations.',
    ],
  },
  SQL_INJECTION: {
    action: 'Harden application against SQL injection',
    priority: 'high',
    summary: 'Classic SQLi probing (OR/AND conditions, UNION SELECT, comments) against web endpoints.',
    steps: [
      'Convert all dynamic SQL on the targeted routes to parameterized queries / prepared statements.',
      'Whitelist input format on endpoints receiving injection probes; reject metacharacters.',
      'Deploy WAF rule set (e.g. OWASP Core Rule Set) with SQLi detection on the affected routes.',
      'Restrict the DB application user to least privilege (read-only where possible) and audit sql error logs.',
    ],
  },
  ADMIN_BRUTE_FORCE: {
    action: 'Harden admin panel against brute force',
    priority: 'high',
    summary: 'Repeated unauthorized access against admin endpoints.',
    steps: [
      'Require 2FA on all /admin, /wp-admin, /administrator logins.',
      'IP-allowlist admin origins; serve admin on a separate hostname or port.',
      'Rate-limit login POSTs (e.g. 3 fails/min/IP, then 15-minute ban via fail2ban or app middleware).',
      'Remove default tool probes (/phpinfo.php) and audit third-party admin plugins.',
    ],
  },
  XSS_PROBE: {
    action: 'Harden against reflected/stored XSS',
    priority: 'medium',
    summary: 'Script injection probes detected against web endpoints.',
    steps: [
      'Set Content-Security-Policy and X-XSS-Protection headers on all responses.',
      'Apply context-aware output encoding wherever user input is rendered.',
      'Sanitize user-controlled input on the targeted routes; reject <script>/event-handler payloads.',
      'Add X-Content-Type-Options: nosniff and frame-ancestors policy.',
    ],
  },
  SCANNER_SIGNATURE: {
    action: 'Block automated scanners at the edge',
    priority: 'medium',
    summary: 'Known scanner tools (acunetix, sqlmap, nikto, nmap) tried to enumerate the service.',
    steps: [
      'Drop requests from known scanner user agents at the reverse proxy.',
      'Add WAF/edge rules for the scanner IPs listed in this report.',
      'Rate-limit 404-heavy source IPs to blunt enumeration.',
      'Monitor for follow-up activity from these sources (they often precede real attacks).',
    ],
  },
  DIRECTORY_FORBIDDEN: {
    action: 'Close browsable server directories',
    priority: 'medium',
    summary: 'Directory-index/forbidden-rule warnings indicate exposed directory listings.',
    steps: [
      'Disable directory listings (Options -Indexes) in the web server config.',
      'Place index files or deny auto-requests on sensitive directories.',
      'Review the forbidden paths for accidentally exposed source/config files.',
    ],
  },
  OTHER: {
    action: 'Review flagged attack traffic',
    priority: 'medium',
    summary: 'Miscellaneous attack traffic flagged by the detection model.',
    steps: [
      'Inspect the flagged request samples in classification for unexpected payloads.',
      'Correlate source IPs with the blocklist nets in this report.',
      'Route known-bad sources to a muted WAF/manual-challenge.',
    ],
  },
};

const PLAYBOOK_ALIASES = { BRUTEFORCE: 'ADMIN_BRUTE_FORCE', XSS: 'XSS_PROBE', SCANNER: 'SCANNER_SIGNATURE' };

/** Family -> regex to scan raw logs for target/route/file/IP extraction. */
const FAMILY_SCAN = {
  CREDENTIAL_PROBE: /\/wp-login|auth\.json|credentials|accessTokens|authorized_keys|\/auth(?:\/|"|'|\s)/i,
  PATH_TRAVERSAL: /\/etc\/(?:passwd|shadow)|\.\.\/|\.\.\\|\/proc\/|\/var\/log|\/\.env|\.config\/gcloud/i,
  SQL_INJECTION: /SELECT[\s\S]{0,20}FROM|UNION\s+SELECT|DROP\s+TABLE|["']?\s*(?:OR|AND)\s+[0-9']|%27|--\s*$/i,
  ADMIN_BRUTE_FORCE: /\/admin(?:\/|$)|\/wp-admin\/|\/administrator\//i,
  XSS_PROBE: /<script|javascript:|onerror\s*=|<xsstag>|domxss/i,
  SCANNER_SIGNATURE: /acunetix|nikto|sqlmap|nmap|wvstest|dirbuster/i,
  DIRECTORY_FORBIDDEN: /Directory index forbidden|forbidden by rule/i,
};

const famKey = (type) => String(type).replace(/^v2:/, '').replace(/-/g, '_').toUpperCase();
const playbookFor = (type) => {
  const key = PLAYBOOK_ALIASES[famKey(type)] || famKey(type);
  return PLAYBOOKS[key] || null;
};
const cap = (arr, n) => arr.slice(0, n);

/**
 * Local Root Cause Analysis — deterministic, no LLM.
 * Produces the same response schema as the LLM RCA endpoint:
 * { rootCause, evidence, causalChain, impact, recommendations, confidence, analysisNotes }
 */
class LocalRootCauseService {
  analyze(options = {}) {
    const startTime = Date.now();
    if (!logStore.isLoaded) {
      throw new Error('No logs loaded. Please upload a log file first.');
    }

    const allDeduped = logStore.getDeduped();
    const errorPatterns = allDeduped
      .filter((d) => ['error', 'crit', 'critical', 'emerg', 'warn', 'warning'].includes(d.level))
      .sort((a, b) => b.occurrenceCount - a.occurrenceCount);

    if (errorPatterns.length === 0) {
      return this._noErrorsResult(startTime);
    }

    const top = errorPatterns.slice(0, 10).map((p) => {
      const cls = rules.classify({ message: p.message, level: p.level, raw: p.raw });
      const v2 = v2Detections.get(p.fingerprint);
      return {
        pattern: p,
        cls: v2 ? { ...cls, category: 'Security' } : cls,
        v2,
      };
    });

    const chains = contextSelector._buildEscalationChains(logStore.logs);
    const securitySignals = contextSelector._detectSecuritySignals(allDeduped);

    // Fold v2 deep-model verdicts in as security signal patterns so the deep
    // classifier's attacks count toward the security-dominant branch.
    for (const t of top) {
      if (t.v2) {
        securitySignals.push({
          type: `v2:${t.v2.attack_type}`,
          message: t.pattern.message,
          occurrenceCount: t.pattern.occurrenceCount || 1,
          timestamp: t.pattern.firstSeen || t.pattern.timestamp,
        });
      }
    }

    // Security is only "dominant" when it accounts for a meaningful share of failures
    const securityCount = securitySignals.reduce((s, sig) => s + (sig.occurrenceCount || 1), 0);
    const totalErrorCount = top.reduce((s, { pattern }) => s + pattern.occurrenceCount, 0);
    const securityDominant = securitySignals.length > 0 && totalErrorCount > 0 && securityCount / totalErrorCount >= 0.3;

    const rootCause = this._rootCause(top, chains, securitySignals, securityDominant);
    const evidence = this._evidence(top);
    const causalChain = this._causalChain(top, chains, securitySignals);
    const impact = this._impact(errorPatterns);
    const targets = this._extractTargets(allDeduped);
    const recommendations = this._recommendations(top, securitySignals, securityDominant, targets);
    const confidence = this._confidence(errorPatterns, top);
    const analysisNotes = `Generated locally via deterministic rules + trained classifier (no LLM). ${errorPatterns.length} error/warning pattern(s) analyzed; top ${top.length} explain the observed failures.`;

    const processingTime = Date.now() - startTime;
    logger.info(`Local RCA: confidence ${confidence} in ${processingTime}ms`);

    return {
      analysis: { rootCause, evidence, causalChain, impact, recommendations, confidence, analysisNotes },
      metadata: {
        totalLogsInDataset: logStore.stats.totalLogs,
        errorLogsAnalyzed: (logStore.getByLevel('error') || []).length,
        uniqueErrorPatterns: errorPatterns.length,
        timeRange: logStore.stats.timeRange,
        analysisScope: options.symptom ? `Symptom: "${options.symptom}"` : 'All Logs',
        engine: 'local',
      },
      processingTimeMs: processingTime,
      usage: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }

  _rootCause(top, chains, securitySignals, securityDominant) {
    if (securityDominant) {
      // Aggregate signal types by count for concise summary
      const typeCounts = {};
      for (const s of securitySignals) {
        typeCounts[s.type] = (typeCounts[s.type] || 0) + (s.occurrenceCount || 1);
      }
      const sorted = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]);
      const top3 = sorted.slice(0, 3).map(([type, cnt]) => `${type} (${cnt})`).join(', ');
      const others = sorted.length > 3 ? ` + ${sorted.length - 3} more` : '';
      return `Security-related events dominate the failures: ${securitySignals.length} signal pattern(s) — primarily ${top3}${others}, indicating external attack or automated scanning activity against the service.`;
    }

    const byCategory = {};
    for (const { pattern, cls } of top) {
      byCategory[cls.category] = (byCategory[cls.category] || 0) + pattern.occurrenceCount;
    }
    const [dominantCat, count] = Object.entries(byCategory).sort((a, b) => b[1] - a[1])[0] || ['Clean', 0];

    const CAUSE_TEXT = {
      'Backend Communication': `The dominant failure is a backend/upstream communication problem: the most frequent error pattern recurred ${count} time(s). Worker/proxy connections to the backend are failing, causing requests to error out.`,
      Network: 'The dominant failure is network-level: connection/socket errors dominate the error stream, suggesting connectivity or DNS instability between service tiers.',
      Performance: 'The dominant failure is performance-related: timeouts and resource exhaustion errors indicate the service is under-provisioned or experiencing latency spikes.',
      'Service Instability': 'The dominant failure is service instability: repeated worker failures indicate a cascading failure or crash-loop pattern.',
      'Resource Not Found': 'The dominant failure is missing resources: requests are hitting endpoints/files that do not exist, producing 404-class errors at volume.',
      Configuration: 'The dominant failure is configuration-related: configuration/initialization errors suggest a misconfiguration introduced at deploy time.',
      Security: 'The dominant failure is security-related: access/authorization errors dominate, indicating forbidden access attempts or misconfigured permissions.',
      Error: `The dominant failure is generic internal errors: the most frequent error pattern recurred ${count} time(s). No single subsystem dominates beyond application exceptions.`,
      Warning: 'The dominant condition is non-critical: warnings dominate without hard failures, indicating recoverable anomalies or resource pressure.',
    };
    const dominantMessage = top[0]?.pattern.message || '';

    if (chains.length > 0) {
      const chain = chains[0];
      return `${CAUSE_TEXT[dominantCat] || 'An operational failure was detected.'} The error was consistently preceded by lower-severity events (${chain.precedingEvents[0]?.message || 'initial activity'} → ${chain.errorLog.message}), indicating a gradual degradation before failure.`;
    }
    return `${CAUSE_TEXT[dominantCat] || 'An operational failure was detected.'} Representative pattern: ${dominantMessage}`;
  }

  _evidence(top) {
    const SIGNIFICANCE = {
      Security: 'External or unauthorized activity; verify and block source.',
      'Backend Communication': 'Backend availability is the failure point.',
      Network: 'Network path between tiers is unreliable.',
      Performance: 'Resource pressure or slow components cause errors.',
      'Service Instability': 'Worker/process lifecycle instability compounds failures.',
      'Resource Not Found': 'Missing assets produce avoidable error volume.',
      Error: 'Application exception path, likely a code/state bug.',
      Warning: 'Precursor condition that may escalate.',
    };
    return top.slice(0, 3).map(({ pattern, cls }) => ({
      finding: `${cls.category} pattern recurring ${pattern.occurrenceCount} time(s)`,
      logPattern: pattern.message.slice(0, 160),
      occurrences: pattern.occurrenceCount,
      significance: SIGNIFICANCE[cls.category] || 'Contributes to the observed error volume.',
    }));
  }

  _causalChain(top, chains, securitySignals) {
    const { start } = logStore.stats.timeRange;
    const chainSteps = [];
    if (chains.length > 0) {
      const chain = chains[0];
      const first = chain.precedingEvents[0];
      if (first) chainSteps.push(`Step 1: Initial trigger — "${first.message.slice(0, 80)}" at ${formatTimelineTimestamp(first.timestamp)}.`);
      const warn = chain.precedingEvents.find((l) => ['warn', 'warning'].includes(l.level));
      if (warn) chainSteps.push(`Step 2: Escalation — warning "${warn.message.slice(0, 80)}" before the failure.`);
      chainSteps.push(`Step 3: Failure — "${chain.errorLog.message.slice(0, 80)}" (×${chain.chainCount}).`);
    } else if (top.length > 0) {
      chainSteps.push(`Step 1: Failures began at ${formatTimelineTimestamp(top[0].pattern.firstSeen || start)}.`);
      chainSteps.push(`Step 2: The dominant pattern recurred ${top[0].pattern.occurrenceCount} time(s).`);
      chainSteps.push(`Step 3: Error volume peaked with ${top[0].cls.category} errors affecting request handling.`);
    }
    if (securitySignals.length > 0) {
      chainSteps.push(`Step ${chainSteps.length + 1}: Security signal "${securitySignals[0].type}" present (×${securitySignals[0].occurrenceCount}).`);
    }
    return chainSteps.length > 0 ? chainSteps : ['Step 1: No escalating failure pattern observed.'] ;
  }

  _impact(errorPatterns) {
    const errorLogs = (logStore.getByLevel('error') || []).length + (logStore.getByLevel('crit') || []).length;
    const total = logStore.stats.totalLogs || 1;
    const pct = Math.round((errorLogs / total) * 100);
    const range = logStore.stats.timeRange;
    return `${errorLogs} of ${total} log lines (${pct}%) were hard errors over ${range.start ? formatTimelineTimestamp(range.start) : 'N/A'} to ${range.end ? formatTimelineTimestamp(range.end) : 'N/A'}. Impact: degraded availability and failed user requests during the affected windows; operators should expect increased error rates and potential customer-facing failures.`;
  }

  /**
   * Concrete intel: which files/routes/IPs are implicated, per attack family.
   * Scans raw logs (not deduped) so every attempt is counted.
   * Returns { topIPs, families: { FAMILY: { files, routes, ips } }, configFiles, notFound }
   */
  _extractTargets(deduped) {
    const allLogs = logStore.logs;
    const targets = { topIPs: [], families: {}, configFiles: [], notFound: [] };

    const ipCounts = {};
    for (const l of allLogs) {
      const ip = l.src_ip;
      if (ip && ip !== '127.0.0.1' && ip !== '::1') ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }
    targets.topIPs = cap(Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).map(([ip, count]) => ({ ip, count })), 5);

    for (const [fam, regex] of Object.entries(FAMILY_SCAN)) {
      const files = {}, routes = {}, ips = {};
      for (const l of allLogs) {
        const text = `${l.raw || ''} ${l.message || ''}`;
        if (!regex.test(text)) continue;
        const q = l.message.match(/'([^']+)/);
        if (q) files[q[1]] = (files[q[1]] || 0) + 1;
        const r = l.message.match(/(?:GET|POST|PUT|DELETE)\s+(\S+)/);
        if (r) routes[r[1]] = (routes[r[1]] || 0) + 1;
        if (l.src_ip && l.src_ip !== '127.0.0.1' && l.src_ip !== '::1') ips[l.src_ip] = (ips[l.src_ip] || 0) + 1;
      }
      targets.families[fam] = {
        files: cap(Object.entries(files).sort((a, b) => b[1] - a[1]).map(([path, count]) => ({ path, count })), 5),
        routes: cap(Object.entries(routes).sort((a, b) => b[1] - a[1]).map(([path, count]) => ({ path, count })), 5),
        ips: cap(Object.entries(ips).sort((a, b) => b[1] - a[1]).map(([ip, count]) => ({ ip, count })), 5),
      };
    }

    const configFiles = {};
    for (const l of allLogs) {
      if (!/rootcheck|Host-based anomaly/i.test(l.message)) continue;
      const m = l.message.match(/'([^']+)/);
      if (m) configFiles[m[1]] = (configFiles[m[1]] || 0) + 1;
    }
    targets.configFiles = cap(Object.entries(configFiles).sort((a, b) => b[1] - a[1]).map(([path, count]) => ({ path, count })), 5);

    const notFoundRoutes = {}, notFoundIps = {};
    for (const l of allLogs) {
      if (!/Web server (?:400|404) error code/i.test(l.message)) continue;
      const r = l.message.match(/(?:GET|POST|PUT)\s+(\S+)/);
      if (r) notFoundRoutes[r[1]] = (notFoundRoutes[r[1]] || 0) + 1;
      if (l.src_ip && l.src_ip !== '127.0.0.1' && l.src_ip !== '::1') notFoundIps[l.src_ip] = (notFoundIps[l.src_ip] || 0) + 1;
    }
    targets.notFound = {
      routes: cap(Object.entries(notFoundRoutes).sort((a, b) => b[1] - a[1]).map(([path, count]) => ({ path, count })), 5),
      ips: cap(Object.entries(notFoundIps).sort((a, b) => b[1] - a[1]).map(([ip, count]) => ({ ip, count })), 5),
    };

    return targets;
  }

  _recommendations(top, securitySignals, securityDominant, targets) {
    const recs = [];
    const cats = new Set(top.map(({ cls }) => cls.category));

    if (securityDominant || top[0]?.cls.category === 'Security') {
      const families = {};
      for (const s of securitySignals) {
        const key = playbookFor(s.type) ? famKey(s.type) : null;
        if (!key) continue;
        families[key] = (families[key] || 0) + (s.occurrenceCount || 1);
      }
      const ranked = Object.entries(families).sort((a, b) => b[1] - a[1]);
      for (const [fam, count] of ranked) {
        const pb = PLAYBOOK_ALIASES[fam] ? PLAYBOOKS[PLAYBOOK_ALIASES[fam]] : PLAYBOOKS[fam];
        if (!pb) continue;
        const t = targets.families[fam] || {};
        // Skip families with no concrete targets — matching on host/JSON noise
        // (e.g. Windows event bodies) yields nothing actionable.
        if (!(t.files?.length || t.routes?.length || t.ips?.length)) continue;
        recs.push({
          action: pb.action,
          priority: pb.priority,
          rationale: `${count} ${fam.toLowerCase().replace(/_/g, ' ')} attempt(s) observed. ${pb.summary}`,
          steps: pb.steps,
          files: t.files || [],
          routes: t.routes || [],
          sources: t.ips || [],
        });
      }
      if (recs.length === 0) {
        recs.push({
          action: 'Block malicious sources and add WAF rules',
          priority: 'high',
          rationale: `Security signals (${[...new Set(securitySignals.map((s) => s.type))].join(', ')}) were detected — restrict offending IPs and tighten access controls.`,
          sources: targets.topIPs,
          steps: [
            'Restrict the offending source IPs at the edge (WAF deny / firewall).',
            'Add alerting on return visits from these sources.',
            'Re-run analysis after blocking to measure residual risk.',
          ],
        });
      }
    }

    if (cats.has('Backend Communication')) {
      recs.push({
        action: 'Verify backend/upstream health and connection pool',
        priority: 'high',
        rationale: 'Backend communication errors dominate; check upstream availability, connection limits, and retry/timeout configuration.',
        steps: [
          'Check upstream service health (load, latency, restarts) over the affected window.',
          'Inspect connection pool/keep-alive and retry settings on the proxy.',
          'Confirm upstream host/DNS resolution is stable.',
        ],
      });
    }
    if (cats.has('Network')) {
      recs.push({
        action: 'Inspect network path, DNS, and firewall rules',
        priority: 'medium',
        rationale: 'Network-level errors indicate connectivity instability between tiers.',
        steps: ['Verify ICMP/TCP reachability across tiers.', 'Check DNS TTL/cache and resolution failures.', 'Review firewall/security-group changes in the incident window.'],
      });
    }
    if (cats.has('Performance') || cats.has('Service Instability')) {
      recs.push({
        action: 'Review resource limits and restart behavior',
        priority: 'high',
        rationale: 'Timeout/resource errors suggest under-provisioning or runaway workers; check memory/CPU and worker pool settings.',
        steps: ['Check memory/CPU saturation and swap during the window.', 'Review worker/thread pool limits and restart counts.', 'Correlate with deploy schedule or traffic spikes.'],
      });
    }
    if (cats.has('Resource Not Found')) {
      recs.push({
        action: 'Reconcile missing endpoints/assets and stop scan floods',
        priority: 'medium',
        rationale: 'High 400/404 volume indicates automated enumeration against routes that do not exist.',
        steps: ['Triage the missed routes listed here (broken links vs. attacker enumeration).', 'Rate-limit or challenge 404-heavy source IPs.', 'Serve a neutral 404 and log scans into a dedicated monitor.'],
        routes: targets.notFound.routes || [],
        sources: targets.notFound.ips || [],
      });
    }
    if (cats.has('Configuration') || cats.has('Startup')) {
      recs.push({
        action: 'Audit configuration/file changes and restore integrity',
        priority: 'high',
        rationale: 'Configuration/rootcheck anomalies were flagged — verify the changed system files against a trusted baseline.',
        steps: [
          'Inspect the flagged files for unauthorized modifications (ownership, permissions, contents).',
          'Restore any changed system/config files from a known-good backup.',
          'Tighten file integrity monitoring (AIDE/OSSEC syscheck) for the listed paths.',
          'Correlate the change window with deploy/access activity.',
        ],
        files: targets.configFiles || [],
      });
    }
    if (recs.length === 0) {
      recs.push({
        action: 'Add structured logging and monitor error-rate baselines',
        priority: 'low',
        rationale: 'No dominant failure category identified; observability will surface the root cause.',
        steps: ['Instrument request/error rates per endpoint.', 'Set detect thresholds on error-rate spikes.', 'Rerun RCA after a window of data.'],
      });
    }
    if (recs.length > 5) recs.length = 5;
    return recs;
  }

  _confidence(errorPatterns, top) {
    const totalErrors = errorPatterns.reduce((s, p) => s + p.occurrenceCount, 0) || 1;
    const explained = top.reduce((s, { pattern }) => s + pattern.occurrenceCount, 0);
    const coverage = explained / totalErrors;
    return Math.min(96, Math.round(62 + coverage * 34));
  }

  _noErrorsResult(startTime) {
    return {
      analysis: {
        rootCause: 'No error or warning patterns detected in the dataset — the service appears healthy.',
        evidence: [],
        causalChain: [],
        impact: 'No failure impact observed.',
        recommendations: [],
        confidence: 90,
        analysisNotes: 'Generated locally (no LLM). Dataset contained no error/warning patterns.',
      },
      metadata: { engine: 'local', totalLogsInDataset: logStore.stats.totalLogs },
      processingTimeMs: Date.now() - startTime,
      usage: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }
}

module.exports = new LocalRootCauseService();
