const logStore = require('../store/logStore');
const contextSelector = require('./contextSelector');
const rules = require('../rules/logRules');
const config = require('../config/app.config');
const { getTimeBucketKey } = require('../utils/helpers');
const logger = require('../utils/logger');

const SEVERE_LEVELS = new Set(['error', 'crit', 'critical', 'emerg', 'alert']);

/**
 * Incident Detection Service — finds incidents WITHOUT any LLM.
 * Detects error bursts, novel templates, and escalation chains over the
 * already-indexed LogStore. Sub-second on 100k+ lines.
 */
class IncidentService {
  detect(options = {}) {
    const startTime = Date.now();
    if (!logStore.isLoaded) {
      throw new Error('No logs loaded. Please upload a log file first.');
    }

    const bucketMinutes = options.bucketMinutes || config.detection.bucketMinutes;
    const zThreshold = options.burstZThreshold ?? config.detection.burstZThreshold;
    const minErrors = options.burstMinErrors || config.detection.burstMinErrors;
    const noveltyFraction = options.noveltyStartFraction ?? config.detection.noveltyStartFraction;

    // ── 1. Bucket logs ─────────────────────────────────────────────────────
    const buckets = new Map();
    for (const log of logStore.logs) {
      if (!log.timestamp) continue;
      const key = getTimeBucketKey(log.timestamp, bucketMinutes);
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push(log);
    }

    // ── 2. Burst detection (z-score on severe-log count per bucket) ────────
    const counts = Array.from(buckets.values()).map((logs) =>
      logs.filter((l) => SEVERE_LEVELS.has(l.level)).length
    );
    const mean = counts.reduce((a, b) => a + b, 0) / (counts.length || 1);
    const variance = counts.reduce((a, b) => a + (b - mean) ** 2, 0) / (counts.length || 1);
    const std = Math.sqrt(variance) || 1;

    const incidents = [];
    for (const [key, logs] of buckets) {
      const severe = logs.filter((l) => SEVERE_LEVELS.has(l.level));
      const z = (severe.length - mean) / std;
      if (severe.length >= minErrors && z >= zThreshold) {
        incidents.push(
          this._buildBurstIncident(key, logs, severe, z, bucketMinutes)
        );
      }
    }

    // ── 3. Novelty detection ───────────────────────────────────────────────
    const novelPatterns = this._findNovelPatterns(noveltyFraction);
    if (novelPatterns.length > 0) {
      incidents.push(this._buildNoveltyIncident(novelPatterns));
    }

    // ── 4. Escalation chains (info → warn → error) ─────────────────────────
    const chains = contextSelector._buildEscalationChains(logStore.logs);
    if (chains.length > 0) {
      incidents.push(this._buildEscalationIncident(chains));
    }

    incidents.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

    const processingTime = Date.now() - startTime;
    logger.info(`Incident detection: ${incidents.length} incidents in ${processingTime}ms`);

    return {
      incidents,
      stats: {
        totalLogs: logStore.stats.totalLogs,
        bucketsAnalyzed: buckets.size,
        bucketMinutes,
        baseline: { meanSeverePerBucket: +mean.toFixed(2), stdSeverePerBucket: +std.toFixed(2) },
        novelPatterns: novelPatterns.length,
        escalationChains: chains.length,
      },
      processingTimeMs: processingTime,
    };
  }

  _bucketTopPatterns(logs, max = 5) {
    const byFp = new Map();
    for (const log of logs) {
      if (!byFp.has(log.fingerprint)) {
        byFp.set(log.fingerprint, { message: log.message, level: log.level, count: 1 });
      } else {
        byFp.get(log.fingerprint).count++;
      }
    }
    return Array.from(byFp.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, max)
      .map((p) => ({ ...p, category: rules.classify(p).category }));
  }

  _buildBurstIncident(windowKey, logs, severe, z, bucketMinutes) {
    const severeCount = severe.length;
    const level = z >= 6 ? 'critical' : 'high';
    return {
      id: `burst-${windowKey}`,
      windowStart: windowKey,
      windowEnd: new Date(new Date(windowKey).getTime() + bucketMinutes * 60000).toISOString(),
      severity: level,
      title: `${severeCount} errors in one ${bucketMinutes}-min window (${z.toFixed(1)}σ above baseline)`,
      summary: `Severe-log count spiked ${z.toFixed(1)} standard deviations above the baseline of ${severeCount}.`,
      logCount: logs.length,
      errorCount: severeCount,
      zScore: +z.toFixed(2),
      topPatterns: this._bucketTopPatterns(severe),
      signals: ['error-burst'],
      type: 'burst',
    };
  }

  _findNovelPatterns(noveltyFraction) {
    const { start, end } = logStore.stats.timeRange;
    if (!start || !end) return [];
    const boundary = new Date(new Date(start).getTime() + (new Date(end) - new Date(start)) * noveltyFraction);
    const novel = [];
    for (const [fp, entries] of logStore.byFingerprint) {
      const first = entries[0];
      if (first.timestamp && new Date(first.timestamp) >= boundary && SEVERE_LEVELS.has(first.level)) {
        const rule = rules.classify({ message: first.message, level: first.level, raw: first.raw });
        novel.push({ fingerprint: fp, message: first.message, level: first.level, count: entries.length, category: rule.category });
      }
    }
    return novel.sort((a, b) => b.count - a.count);
  }

  _buildNoveltyIncident(patterns) {
    return {
      id: 'novelty',
      windowStart: null,
      windowEnd: null,
      severity: 'medium',
      title: `${patterns.length} new error patterns appeared late in the dataset`,
      summary: `Templates not seen earlier in the log stream started appearing in the latter portion of the data — possible configuration drift or new attack surface.`,
      logCount: patterns.reduce((s, p) => s + p.count, 0),
      errorCount: patterns.reduce((s, p) => s + (SEVERE_LEVELS.has(p.level) ? p.count : 0), 0),
      zScore: null,
      topPatterns: patterns.slice(0, 5).map((p) => ({ message: p.message, level: p.level, count: p.count, category: p.category })),
      signals: ['novelty'],
      type: 'novelty',
    };
  }

  _buildEscalationIncident(chains) {
    const top = chains.slice(0, 5).map((c) => ({
      message: c.errorLog.message,
      level: c.errorLog.level,
      count: c.chainCount,
      category: rules.classify(c.errorLog).category,
    }));
    return {
      id: 'escalation',
      windowStart: null,
      windowEnd: null,
      severity: 'high',
      title: `${chains.length} info→warning→error escalation chains detected`,
      summary: `Errors were consistently preceded by lower-severity warnings and notices — the system degrades gradually before failing.`,
      logCount: chains.reduce((s, c) => s + c.precedingEvents.length + 1, 0),
      errorCount: chains.reduce((s, c) => s + c.chainCount, 0),
      zScore: null,
      topPatterns: top,
      signals: ['escalation-chain'],
      type: 'escalation',
    };
  }
}

function severityRank(sev) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[sev] || 0;
}

module.exports = new IncidentService();
