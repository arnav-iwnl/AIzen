const logger = require('../utils/logger');
const { getHourlyBucketKey, getTimeBucketKey } = require('../utils/helpers');

/**
 * LogStore — In-Memory Log Storage Engine (Singleton)
 *
 * Holds all parsed logs in memory with multiple indexes for fast lookups.
 * No database — all data lives in JavaScript Maps and Arrays.
 *
 * Indexes:
 * - byId:          Map<logId, logEntry>         — O(1) lookup by ID
 * - byLevel:       Map<level, logEntry[]>       — Fast filter by severity
 * - byTimeWindow:  Map<bucketKey, logEntry[]>   — Temporal grouping (15-min buckets)
 * - byHour:        Map<hourKey, logEntry[]>      — Hourly grouping
 * - byFingerprint: Map<fingerprint, logEntry[]> — Deduplication groups
 */
class LogStore {
  constructor() {
    this.logs = [];                    // All logs, chronologically sorted
    this.byId = new Map();            // logId → log entry
    this.byLevel = new Map();         // "error" → [log, log, ...]
    this.byTimeWindow = new Map();    // "2005-12-04T04:45:00Z" → [log, ...]
    this.byHour = new Map();          // "2005-12-04T04:00:00Z" → [log, ...]
    this.byFingerprint = new Map();   // fingerprint → [log, ...]

    this.stats = {
      totalLogs: 0,
      countByLevel: {},
      timeRange: { start: null, end: null },
      uniquePatterns: 0,
      topPatterns: [],
      parseErrors: 0,
    };

    this.isLoaded = false;
    this.loadedAt = null;
    this.sourceFile = null;
  }

  /**
   */
  clearStore() {
    this.logs = [];
    this.byId.clear();
    this.byLevel.clear();
    this.byTimeWindow.clear();
    this.byHour.clear();
    this.byFingerprint.clear();

    this.stats = {
      totalLogs: 0,
      countByLevel: {},
      timeRange: { start: null, end: null },
      uniquePatterns: 0,
      topPatterns: [],
      parseErrors: 0,
    };

    this.isLoaded = false;
    this.loadedAt = null;
    this.sourceFile = null;
  }

  /**
   * Append a batch of parsed logs to the unindexed array.
   * Call finalizeIngest() after all batches are added.
   * @param {Object[]} parsedLogs - Array of parsed log entries
   */
  ingestBatch(parsedLogs) {
    this.logs.push(...parsedLogs);
  }

  /**
   * Sort all logs chronologically, build indexes, and compute stats.
   * @param {string} sourceFile - Original file name
   */
  finalizeIngest(sourceFile = 'unknown') {
    this.sourceFile = sourceFile;

    // Sort chronologically by timestamp
    this.logs.sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return new Date(a.timestamp) - new Date(b.timestamp);
    });

    // Build all indexes
    for (const log of this.logs) {
      // Index by ID
      this.byId.set(log.id, log);

      // Index by level
      if (!this.byLevel.has(log.level)) {
        this.byLevel.set(log.level, []);
      }
      this.byLevel.get(log.level).push(log);

      // Index by time window (15-minute buckets)
      if (log.timestamp) {
        const windowKey = getTimeBucketKey(log.timestamp, 15);
        if (!this.byTimeWindow.has(windowKey)) {
          this.byTimeWindow.set(windowKey, []);
        }
        this.byTimeWindow.get(windowKey).push(log);

        // Index by hour
        const hourKey = getHourlyBucketKey(log.timestamp);
        if (!this.byHour.has(hourKey)) {
          this.byHour.set(hourKey, []);
        }
        this.byHour.get(hourKey).push(log);
      }

      // Index by fingerprint
      if (!this.byFingerprint.has(log.fingerprint)) {
        this.byFingerprint.set(log.fingerprint, []);
      }
      this.byFingerprint.get(log.fingerprint).push(log);
    }

    // Compute stats
    this._computeStats();

    this.isLoaded = true;
    this.loadedAt = new Date().toISOString();

    logger.info('LogStore finalized stream ingestion', {
      total: this.stats.totalLogs,
      uniquePatterns: this.stats.uniquePatterns,
      levels: this.stats.countByLevel,
      timeRange: this.stats.timeRange,
    });
  }

  /**
   * Ingest parsed log entries into the store and build all indexes.
   * @param {Object[]} parsedLogs - Array of parsed log entries
   * @param {string} sourceFile - Original file name
   */
  ingest(parsedLogs, sourceFile = 'unknown') {
    this.clear();
    this.sourceFile = sourceFile;

    // Sort chronologically by timestamp
    const sorted = [...parsedLogs].sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return new Date(a.timestamp) - new Date(b.timestamp);
    });

    this.logs = sorted;

    // Build all indexes
    for (const log of sorted) {
      // Index by ID
      this.byId.set(log.id, log);

      // Index by level
      if (!this.byLevel.has(log.level)) {
        this.byLevel.set(log.level, []);
      }
      this.byLevel.get(log.level).push(log);

      // Index by time window (15-minute buckets)
      if (log.timestamp) {
        const windowKey = getTimeBucketKey(log.timestamp, 15);
        if (!this.byTimeWindow.has(windowKey)) {
          this.byTimeWindow.set(windowKey, []);
        }
        this.byTimeWindow.get(windowKey).push(log);

        // Index by hour
        const hourKey = getHourlyBucketKey(log.timestamp);
        if (!this.byHour.has(hourKey)) {
          this.byHour.set(hourKey, []);
        }
        this.byHour.get(hourKey).push(log);
      }

      // Index by fingerprint
      if (!this.byFingerprint.has(log.fingerprint)) {
        this.byFingerprint.set(log.fingerprint, []);
      }
      this.byFingerprint.get(log.fingerprint).push(log);
    }

    // Compute stats
    this._computeStats();

    this.isLoaded = true;
    this.loadedAt = new Date().toISOString();

    logger.info('LogStore ingested logs', {
      total: this.stats.totalLogs,
      uniquePatterns: this.stats.uniquePatterns,
      levels: this.stats.countByLevel,
      timeRange: this.stats.timeRange,
    });
  }

  /**
   * Pre-compute statistics about the log dataset.
   */
  _computeStats() {
    this.stats.totalLogs = this.logs.length;

    // Count by level
    this.stats.countByLevel = {};
    for (const [level, entries] of this.byLevel) {
      this.stats.countByLevel[level] = entries.length;
    }

    // Time range
    const withTimestamps = this.logs.filter((l) => l.timestamp);
    if (withTimestamps.length > 0) {
      this.stats.timeRange.start = withTimestamps[0].timestamp;
      this.stats.timeRange.end = withTimestamps[withTimestamps.length - 1].timestamp;
    }

    // Unique patterns
    this.stats.uniquePatterns = this.byFingerprint.size;

    // Top patterns (most frequent)
    this.stats.topPatterns = Array.from(this.byFingerprint.entries())
      .map(([fp, entries]) => ({
        fingerprint: fp,
        count: entries.length,
        level: entries[0].level,
        sampleMessage: entries[0].message,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  /**
   * Get logs by their IDs.
   * @param {string[]} ids - Array of log IDs
   * @returns {Object[]} Matching log entries
   */
  getByIds(ids) {
    return ids.map((id) => this.byId.get(id)).filter(Boolean);
  }

  /**
   * Get logs by severity level.
   * @param {string} level - e.g., "error", "notice"
   * @returns {Object[]}
   */
  getByLevel(level) {
    return this.byLevel.get(level) || [];
  }

  /**
   * Get logs within a time range.
   * @param {string} startTime - ISO 8601 start
   * @param {string} endTime - ISO 8601 end
   * @returns {Object[]}
   */
  getByTimeRange(startTime, endTime) {
    const start = new Date(startTime);
    const end = new Date(endTime);
    return this.logs.filter((log) => {
      if (!log.timestamp) return false;
      const t = new Date(log.timestamp);
      return t >= start && t <= end;
    });
  }

  /**
   * Get a context window of logs around a specific log index.
   * @param {number} centerIndex - Index in the sorted logs array
   * @param {number} windowSize - Number of logs on each side
   * @returns {Object[]}
   */
  getWindow(centerIndex, windowSize = 5) {
    const start = Math.max(0, centerIndex - windowSize);
    const end = Math.min(this.logs.length - 1, centerIndex + windowSize);
    return this.logs.slice(start, end + 1);
  }

  /**
   * Get deduplicated logs — one representative per fingerprint group.
   * Includes occurrence count for each pattern.
   * @returns {Object[]} Deduplicated entries with count
   */
  getDeduped() {
    const deduped = [];
    for (const [fingerprint, entries] of this.byFingerprint) {
      deduped.push({
        ...entries[0],                                              // Representative entry
        occurrenceCount: entries.length,                            // How many times this pattern appears
        firstSeen: entries[0].timestamp,                           // Earliest occurrence
        lastSeen: entries[entries.length - 1].timestamp,           // Latest occurrence
        allIds: entries.map((e) => e.id),                          // All IDs in this group
      });
    }
    return deduped.sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return new Date(a.timestamp) - new Date(b.timestamp);
    });
  }

  /**
   * Search logs by keyword in message.
   * @param {string} keyword - Search term
   * @returns {Object[]} Matching logs
   */
  search(keyword) {
    const words = keyword.toLowerCase().split(/\s+/).filter(Boolean);
    return this.logs.filter((log) => {
      const lowerRaw = log.raw.toLowerCase();
      return words.every((word) => lowerRaw.includes(word));
    });
  }

  /**
   * Get a stratified sample of logs (for LLM context).
   * Samples proportionally across levels and time.
   * @param {number} maxCount - Maximum number of logs to return
   * @returns {Object[]}
   */
  getSample(maxCount = 50) {
    if (this.logs.length <= maxCount) return [...this.logs];

    // Proportional sampling by level
    const sampled = [];
    const ratio = maxCount / this.logs.length;

    for (const [level, entries] of this.byLevel) {
      const count = Math.max(1, Math.round(entries.length * ratio));
      const step = entries.length / count;
      for (let i = 0; i < count && sampled.length < maxCount; i++) {
        sampled.push(entries[Math.floor(i * step)]);
      }
    }

    return sampled.sort((a, b) => {
      if (!a.timestamp || !b.timestamp) return 0;
      return new Date(a.timestamp) - new Date(b.timestamp);
    });
  }

  /**
   * Get the index of a log by its ID in the sorted array.
   */
  getIndexById(logId) {
    return this.logs.findIndex((l) => l.id === logId);
  }

  /**
   * Get all error and warning logs with surrounding context.
   * @param {number} contextSize - Logs on each side of error
   * @returns {Object[]}
   */
  getErrorsWithContext(contextSize = 5) {
    const errorIndices = [];
    for (let i = 0; i < this.logs.length; i++) {
      if (this.logs[i].level === 'error' || this.logs[i].level === 'crit' || this.logs[i].level === 'warn') {
        errorIndices.push(i);
      }
    }

    // Merge overlapping windows
    const windows = [];
    let currentStart = null;
    let currentEnd = null;

    for (const idx of errorIndices) {
      const start = Math.max(0, idx - contextSize);
      const end = Math.min(this.logs.length - 1, idx + contextSize);

      if (currentStart === null) {
        currentStart = start;
        currentEnd = end;
      } else if (start <= currentEnd + 1) {
        currentEnd = Math.max(currentEnd, end);
      } else {
        windows.push({ start: currentStart, end: currentEnd });
        currentStart = start;
        currentEnd = end;
      }
    }
    if (currentStart !== null) {
      windows.push({ start: currentStart, end: currentEnd });
    }

    // Extract logs from windows (no duplicates)
    const result = [];
    const seen = new Set();
    for (const window of windows) {
      for (let i = window.start; i <= window.end; i++) {
        if (!seen.has(this.logs[i].id)) {
          seen.add(this.logs[i].id);
          result.push({ ...this.logs[i], isError: this.logs[i].level === 'error' || this.logs[i].level === 'crit' });
        }
      }
    }

    return result;
  }

  /**
   * Get store statistics.
   */
  getStats() {
    return {
      ...this.stats,
      isLoaded: this.isLoaded,
      loadedAt: this.loadedAt,
      sourceFile: this.sourceFile,
      memoryUsage: {
        logsCount: this.logs.length,
        indexedLevels: this.byLevel.size,
        timeWindows: this.byTimeWindow.size,
        hourlyBuckets: this.byHour.size,
        uniqueFingerprints: this.byFingerprint.size,
      },
    };
  }

  /**
   * Clear all data from the store.
   */
  clear() {
    this.clearStore();
  }
}

// Export as singleton
module.exports = new LogStore();
