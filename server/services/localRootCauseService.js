const logStore = require('../store/logStore');
const contextSelector = require('./contextSelector');
const rules = require('../rules/logRules');
const { formatTimelineTimestamp } = require('../utils/helpers');
const logger = require('../utils/logger');

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

    const top = errorPatterns.slice(0, 10).map((p) => ({
      pattern: p,
      cls: rules.classify({ message: p.message, level: p.level, raw: p.raw }),
    }));

    const chains = contextSelector._buildEscalationChains(logStore.logs);
    const securitySignals = contextSelector._detectSecuritySignals(allDeduped);

    // Security is only "dominant" when it accounts for a meaningful share of failures
    const securityCount = securitySignals.reduce((s, sig) => s + (sig.occurrenceCount || 1), 0);
    const totalErrorCount = top.reduce((s, { pattern }) => s + pattern.occurrenceCount, 0);
    const securityDominant = securitySignals.length > 0 && totalErrorCount > 0 && securityCount / totalErrorCount >= 0.3;

    const rootCause = this._rootCause(top, chains, securitySignals, securityDominant);
    const evidence = this._evidence(top);
    const causalChain = this._causalChain(top, chains, securitySignals);
    const impact = this._impact(errorPatterns);
    const recommendations = this._recommendations(top, securitySignals, securityDominant);
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
      const types = securitySignals.map((s) => s.type).join(', ');
      return `Security-related events dominate the failures: ${securitySignals.length} signal pattern(s) (${types}) were observed, indicating external attack or automated scanning activity against the service.`;
    }

    const byCategory = {};
    for (const { pattern, cls } of top) {
      byCategory[cls.category] = (byCategory[cls.category] || 0) + pattern.occurrenceCount;
    }
    const [dominantCat, count] = Object.entries(byCategory).sort((a, b) => b[1] - a[1])[0] || ['Unknown', 0];

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

  _recommendations(top, securitySignals, securityDominant) {
    const recs = [];
    const cats = new Set(top.map(({ cls }) => cls.category));

    if (securityDominant || top[0]?.cls.category === 'Security') {
      recs.push({
        action: 'Block malicious sources and add WAF rules',
        priority: 'high',
        rationale: `Security signals (${securitySignals.map((s) => s.type).join(', ') || 'access violations'}) were detected — restrict offending IPs and tighten access controls.`,
      });
    }
    if (cats.has('Backend Communication')) {
      recs.push({
        action: 'Verify backend/upstream health and connection pool',
        priority: 'high',
        rationale: 'Backend communication errors dominate; check upstream availability, connection limits, and retry/timeout configuration.',
      });
    }
    if (cats.has('Network')) {
      recs.push({
        action: 'Inspect network path, DNS, and firewall rules',
        priority: 'medium',
        rationale: 'Network-level errors indicate connectivity instability between tiers.',
      });
    }
    if (cats.has('Performance') || cats.has('Service Instability')) {
      recs.push({
        action: 'Review resource limits and restart behavior',
        priority: 'high',
        rationale: 'Timeout/resource errors suggest under-provisioning or runaway workers; check memory/CPU and worker pool settings.',
      });
    }
    if (cats.has('Resource Not Found')) {
      recs.push({
        action: 'Reconcile missing endpoints/assets',
        priority: 'medium',
        rationale: 'High 404 volume indicates broken links, removed routes, or stale client references.',
      });
    }
    if (cats.has('Configuration') || cats.has('Startup')) {
      recs.push({
        action: 'Audit configuration and restart sequence',
        priority: 'high',
        rationale: 'Configuration/initialization errors are usually deployment-time issues.',
      });
    }
    if (recs.length === 0) {
      recs.push({
        action: 'Add structured logging and monitor error-rate baselines',
        priority: 'low',
        rationale: 'No dominant failure category identified; observability will surface the root cause.',
      });
    }
    if (recs.length > 3) recs.length = 3;
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
