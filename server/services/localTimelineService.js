const logStore = require('../store/logStore');
const contextSelector = require('./contextSelector');
const rules = require('../rules/logRules');
const { formatTimelineTimestamp } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * Local Incident Timeline — deterministic, no LLM.
 * Produces the same response schema as the LLM timeline endpoint so the
 * frontend is unchanged: { timeline, overallSummary }.
 */
class LocalTimelineService {
  generateTimeline(options = {}) {
    const startTime = Date.now();
    if (!logStore.isLoaded) {
      throw new Error('No logs loaded. Please upload a log file first.');
    }

    const allDeduped = logStore.getDeduped();
    const focus = options.focus || 'errors';
    const primary = allDeduped.filter((d) =>
      focus === 'errors'
        ? ['error', 'crit', 'critical', 'emerg'].includes(d.level)
        : d.level !== 'info'
    );

    const events = [];
    const seenFps = new Set();

    // 1. Escalation chains → events with escalationPath populated
    const chains = contextSelector._buildEscalationChains(logStore.logs);
    const chainsByFp = new Map();
    for (const chain of chains) {
      const fp = chain.errorLog.fingerprint || chain.errorLog.message;
      if (!chainsByFp.has(fp)) chainsByFp.set(fp, chain);
    }

    // 2. Security signals → an aggregate security event
    const securitySignals = contextSelector._detectSecuritySignals(allDeduped);
    if (securitySignals.length > 0) {
      events.push(this._securityEvent(securitySignals));
    }

    // 3. Top error/warning patterns → per-pattern events
    const top = primary
      .filter((d) => !['unknown'].includes(d.level))
      .sort((a, b) => b.occurrenceCount - a.occurrenceCount)
      .slice(0, options.maxEvents || 12);

    for (const pattern of top) {
      const cls = rules.classify({ message: pattern.message, level: pattern.level, raw: pattern.raw });
      const chain = chainsByFp.get(pattern.fingerprint);

      events.push({
        timestamp: formatTimelineTimestamp(pattern.firstSeen || pattern.timestamp),
        eventTitle: this._eventTitle(cls.category, pattern.message),
        severity: this._severityForLevel(pattern.level, cls.category),
        summary: this._summary(pattern, cls),
        escalationPath: this._escalationPath(chain, pattern),
        supportingEvidence: [`${pattern.message} (×${pattern.occurrenceCount})`],
        affectedComponents: this._components(cls.category, pattern),
        category: cls.category,
        _fingerprint: pattern.fingerprint,
      });
      seenFps.add(pattern.fingerprint);
    }

    // Dedupe security event vs individual security-pattern events by fingerprint
    const eventsOut = events
      .filter((e) => !(e._fingerprint && seenFps.has(e._fingerprint) && e.category === 'Security' && e.severity === 'error'))
      .map(({ _fingerprint, ...rest }) => rest);

    eventsOut.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const overallSummary = this._overallSummary(allDeduped, chains.length, securitySignals.length);
    const processingTime = Date.now() - startTime;
    logger.info(`Local timeline: ${eventsOut.length} events in ${processingTime}ms`);

    return {
      timeline: eventsOut,
      overallSummary,
      metadata: {
        totalLogsAnalyzed: logStore.stats.totalLogs,
        uniquePatternsUsed: logStore.stats.uniquePatterns,
        timeRange: logStore.stats.timeRange,
        focus,
        eventsGenerated: eventsOut.length,
        engine: 'local',
      },
      processingTimeMs: processingTime,
      usage: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }

  _severityForLevel(level, category) {
    if (['error', 'crit', 'critical', 'emerg'].includes(level)) return 'error';
    if (['warn', 'warning'].includes(level)) return 'warning';
    if (category === 'Security') return 'error';
    return 'info';
  }

  _eventTitle(category, message) {
    const CATEGORY_TITLES = {
      Security: 'Security event detected',
      'Backend Communication': 'Backend/upstream communication failure',
      Network: 'Network anomaly detected',
      Performance: 'Performance degradation',
      'Service Instability': 'Service instability / cascading failures',
      'Resource Not Found': 'Missing resources returning errors',
      Startup: 'Service startup',
      Shutdown: 'Service shutdown',
      Configuration: 'Configuration issue',
      'Worker Initialization': 'Worker process event',
      Error: 'Internal server error',
      Warning: 'Recoverable warning',
      'Request Processing': 'Request processing activity',
    };
    const short = message.replace(/^\[?client\s+[\d.]+]?\s*/i, '').slice(0, 70);
    return `${CATEGORY_TITLES[category] || 'Log event'}: ${short}`;
  }

  _summary(pattern, cls) {
    const range =
      pattern.firstSeen && pattern.lastSeen
        ? `${formatTimelineTimestamp(pattern.firstSeen)} → ${formatTimelineTimestamp(pattern.lastSeen)}`
        : '';
    return `${cls.category} pattern occurred ${pattern.occurrenceCount} time${pattern.occurrenceCount > 1 ? 's' : ''}${range ? ` (${range})` : ''}. ${cls.insight || ''}`.trim();
  }

  _escalationPath(chain, pattern) {
    if (chain) {
      return [
        ...chain.precedingEvents.map((l) => ({
          level: l.level === 'warning' ? 'warning' : l.level,
          description: l.message.slice(0, 120),
          timestamp: formatTimelineTimestamp(l.timestamp),
        })),
        {
          level: chain.errorLog.level === 'crit' ? 'critical' : 'error',
          description: chain.errorLog.message.slice(0, 120),
          timestamp: formatTimelineTimestamp(chain.errorLog.timestamp),
        },
      ];
    }
    // Fall back to the pattern itself when no chain matched
    return [
      {
        level: pattern.level === 'crit' ? 'critical' : 'error',
        description: pattern.message.slice(0, 120),
        timestamp: formatTimelineTimestamp(pattern.firstSeen || pattern.timestamp),
      },
    ];
  }

  _components(category, pattern) {
    const COMPONENTS = {
      'Backend Communication': ['backend worker', 'upstream', 'mod_jk'],
      Network: ['network', 'socket'],
      Security: ['web application', 'access control'],
      Startup: ['application server'],
      Shutdown: ['application server'],
      Configuration: ['configuration'],
      'Worker Initialization': ['worker processes'],
      Performance: ['resources'],
      'Service Instability': ['worker pool'],
      'Resource Not Found': ['web root', 'filesystem'],
    };
    const comps = [...(COMPONENTS[category] || [])];
    const ip = (pattern.raw || '').match(/client\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
    if (ip) comps.push(`client ${ip[1]}`);
    return comps;
  }

  _securityEvent(signals) {
    const byType = {};
    for (const s of signals) byType[s.type] = (byType[s.type] || 0) + s.occurrenceCount;
    const types = Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .map(([t, n]) => `${t} (×${n})`)
      .join(', ');
    return {
      timestamp: formatTimelineTimestamp(signals[0].timestamp || logStore.stats.timeRange.start),
      eventTitle: 'Security activity detected across log stream',
      severity: 'critical',
      summary: `${signals.length} security signal pattern(s) found: ${types}. Review source IPs and block malicious traffic.`,
      escalationPath: [],
      supportingEvidence: signals.slice(0, 5).map((s) => `${s.type}: ${s.message} (×${s.occurrenceCount})`),
      affectedComponents: ['web application', 'access control'],
      category: 'Security',
    };
  }

  _overallSummary(allDeduped, chainCount, signalCount) {
    const { start, end } = logStore.stats.timeRange;
    const errorPatterns = allDeduped.filter((d) => ['error', 'crit', 'critical', 'emerg'].includes(d.level));
    const dist = {};
    for (const d of errorPatterns) {
      const c = rules.classify(d).category;
      dist[c] = (dist[c] || 0) + d.occurrenceCount;
    }
    const dominant = Object.entries(dist).sort((a, b) => b[1] - a[1])[0]?.[0] || 'None';
    const parts = [
      `Analyzed ${logStore.stats.totalLogs} log lines (${allDeduped.length} unique patterns) over ${start ? formatTimelineTimestamp(start) : 'N/A'} to ${end ? formatTimelineTimestamp(end) : 'N/A'}.`,
      `Dominant issue category: ${dominant}.`,
    ];
    if (chainCount > 0) parts.push(`${chainCount} info→warning→error escalation chain(s) identified.`);
    if (signalCount > 0) parts.push(`${signalCount} security signal pattern(s) detected.`);
    return parts.join(' ');
  }
}

module.exports = new LocalTimelineService();
