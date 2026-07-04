const logStore = require('../store/logStore');
const { groupBy, stratifiedSample } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * Context Selector Service
 *
 * The CRITICAL layer that prevents sending all 2000+ logs to the LLM.
 * Each API feature gets a tailored context selection strategy that
 * dramatically reduces token usage while preserving analytical value.
 */
class ContextSelector {
  /**
   * Build context for LOG CLASSIFICATION from deduplicated patterns.
   * Sends ALL unique patterns with occurrence counts for comprehensive classification.
   *
   * @param {Object[]} patterns - Deduplicated log patterns (from logStore.getDeduped())
   * @returns {string} Formatted context string for the LLM
   */
  buildClassificationContext(patterns) {
    const parts = [];

    // Dataset summary header
    parts.push(`=== LOG DATASET SUMMARY ===`);
    parts.push(`Total logs in dataset: ${logStore.stats.totalLogs}`);
    parts.push(`Unique patterns to classify: ${patterns.length}`);
    parts.push(`Time range: ${logStore.stats.timeRange.start || 'N/A'} to ${logStore.stats.timeRange.end || 'N/A'}`);
    parts.push(`Level distribution: ${JSON.stringify(logStore.stats.countByLevel)}`);
    parts.push('');

    // Each deduplicated pattern with metadata
    parts.push(`=== DEDUPLICATED LOG PATTERNS ===`);
    for (const pattern of patterns) {
      parts.push(`[ID: ${pattern.id}]`);
      parts.push(`  Level: ${pattern.level}`);
      parts.push(`  Message: ${pattern.message}`);
      parts.push(`  Occurrences: ${pattern.occurrenceCount}`);
      parts.push(`  First seen: ${pattern.firstSeen || 'N/A'}`);
      parts.push(`  Last seen: ${pattern.lastSeen || 'N/A'}`);
      parts.push(`  Raw: ${pattern.raw}`);
      parts.push('');
    }

    return parts.join('\n');
  }

  /**
   * Build context for INCIDENT TIMELINE.
   * Deduplicates by fingerprint → one representative per pattern with counts.
   * Groups by time windows for chronological structure.
   *
   * @param {Object} options - { startTime, endTime, focus }
   * @returns {string} Formatted context string for the LLM
   */
  buildTimelineContext(options = {}) {
    let logs = logStore.logs;

    // Filter by time range if specified
    if (options.startTime && options.endTime) {
      logs = logStore.getByTimeRange(options.startTime, options.endTime);
    }

    // Get all deduplicated patterns from the full dataset
    const allDeduped = logStore.getDeduped();

    // Separate error and non-error patterns
    const errorDeduped = allDeduped.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'warn');
    const nonErrorDeduped = allDeduped.filter((d) => d.level !== 'error' && d.level !== 'crit' && d.level !== 'warn');

    // If focus is 'errors', only use error patterns for timeline. Otherwise use all.
    const primaryPatterns = (options.focus === 'errors') ? errorDeduped : allDeduped;

    // Group by hourly time windows for timeline structure
    const byHour = groupBy(primaryPatterns, (log) => {
      if (!log.timestamp) return 'unknown-time';
      const date = new Date(log.timestamp);
      return `${date.toISOString().substring(0, 13)}:00`;
    });

    // Format for LLM
    const contextParts = [];
    contextParts.push(`=== LOG DATASET SUMMARY ===`);
    contextParts.push(`Total logs in file: ${logStore.stats.totalLogs}`);
    contextParts.push(`Unique log patterns: ${allDeduped.length}`);
    contextParts.push(`Error/Warning patterns: ${errorDeduped.length}`);
    contextParts.push(`Time range: ${logStore.stats.timeRange.start} to ${logStore.stats.timeRange.end}`);
    contextParts.push(`Levels breakdown: ${JSON.stringify(logStore.stats.countByLevel)}`);
    contextParts.push('');

    // Primary patterns (errors) grouped by time
    contextParts.push(`=== ERROR/WARNING PATTERNS BY TIME WINDOW ===`);
    for (const [hourKey, entries] of byHour) {
      contextParts.push(`\n--- ${hourKey} ---`);
      for (const entry of entries) {
        contextParts.push(
          `[${entry.level.toUpperCase()}] ${entry.message}` +
          ` | x${entry.occurrenceCount}` +
          ` | First: ${entry.firstSeen || 'N/A'} | Last: ${entry.lastSeen || 'N/A'}`
        );
      }
    }

    // Add top non-error patterns as supplementary context (the LLM needs to
    // see what normal operations look like to reason about what went wrong)
    if (nonErrorDeduped.length > 0) {
      contextParts.push('');
      contextParts.push(`=== SUPPLEMENTARY: TOP NON-ERROR PATTERNS (for operational context) ===`);
      const topNonError = nonErrorDeduped
        .sort((a, b) => b.occurrenceCount - a.occurrenceCount)
        .slice(0, 10);
      for (const entry of topNonError) {
        contextParts.push(
          `[${entry.level.toUpperCase()}] ${entry.message}` +
          ` | x${entry.occurrenceCount}` +
          ` | First: ${entry.firstSeen || 'N/A'} | Last: ${entry.lastSeen || 'N/A'}`
        );
      }
    }

    const context = contextParts.join('\n');
    logger.debug(`Timeline context: ${primaryPatterns.length} primary patterns, ${nonErrorDeduped.length} supplementary (${context.length} chars)`);
    return context;
  }

  /**
   * Build context for ROOT CAUSE ANALYSIS.
   * Focuses on errors/warnings with surrounding context windows.
   *
   * @param {Object} options - { logIds, timeRange, symptom }
   * @returns {string} Formatted context string for the LLM
   */
  buildRootCauseContext(options = {}) {
    let errorLogs;

    if (options.logIds && options.logIds.length > 0) {
      // User specified specific logs — get them + context
      const targetLogs = logStore.getByIds(options.logIds);
      const contextLogs = [];
      for (const log of targetLogs) {
        const idx = logStore.getIndexById(log.id);
        if (idx >= 0) {
          const window = logStore.getWindow(idx, 5);
          contextLogs.push(...window);
        }
      }
      // Deduplicate
      const seen = new Set();
      errorLogs = contextLogs.filter((l) => {
        if (seen.has(l.id)) return false;
        seen.add(l.id);
        return true;
      });
    } else if (options.timeRange) {
      // Filter by time range
      errorLogs = logStore.getByTimeRange(options.timeRange.start, options.timeRange.end);
    } else if (options.symptom) {
      // Search by symptom keyword and get context
      const found = logStore.search(options.symptom);
      const contextLogs = [];
      for (const log of found) {
        const idx = logStore.getIndexById(log.id);
        if (idx >= 0) {
          contextLogs.push(...logStore.getWindow(idx, 5));
        }
      }
      const seen = new Set();
      errorLogs = contextLogs.filter((l) => {
        if (seen.has(l.id)) return false;
        seen.add(l.id);
        return true;
      });

      if (errorLogs.length === 0) {
        logger.warn(`No logs found matching symptom: "${options.symptom}". Falling back to all errors.`);
        errorLogs = logStore.getErrorsWithContext(5);
      }
    } else {
      // Default: get all errors with context
      errorLogs = logStore.getErrorsWithContext(5);
    }

    // Deduplicate for the prompt
    const fingerprints = new Map();
    for (const log of errorLogs) {
      if (!fingerprints.has(log.fingerprint)) {
        fingerprints.set(log.fingerprint, {
          representative: log,
          count: 1,
          allTimestamps: [log.timestamp],
          ids: [log.id],
        });
      } else {
        const group = fingerprints.get(log.fingerprint);
        group.count++;
        group.allTimestamps.push(log.timestamp);
        group.ids.push(log.id);
      }
    }

    // Format for LLM
    const contextParts = [];
    contextParts.push(`=== ROOT CAUSE ANALYSIS CONTEXT ===`);
    contextParts.push(`Total logs in dataset: ${logStore.stats.totalLogs}`);
    contextParts.push(`Error/Warning logs analyzed: ${errorLogs.length}`);
    contextParts.push(`Unique error patterns: ${fingerprints.size}`);
    contextParts.push(`Time range: ${logStore.stats.timeRange.start} to ${logStore.stats.timeRange.end}`);
    contextParts.push('');

    // Error patterns summary
    contextParts.push(`=== ERROR PATTERNS ===`);
    for (const [fp, group] of fingerprints) {
      const log = group.representative;
      contextParts.push(
        `[${log.level.toUpperCase()}] ${log.message}` +
        ` | Occurrences: ${group.count}` +
        ` | First: ${group.allTimestamps[0] || 'N/A'}` +
        ` | Last: ${group.allTimestamps[group.allTimestamps.length - 1] || 'N/A'}` +
        ` | IDs: ${group.ids.slice(0, 5).join(', ')}${group.ids.length > 5 ? '...' : ''}`
      );
    }

    // Chronological sequence of unique events (for causality analysis)
    contextParts.push('');
    contextParts.push(`=== CHRONOLOGICAL EVENT SEQUENCE ===`);
    const chronological = stratifiedSample(errorLogs, 60);
    for (const log of chronological) {
      contextParts.push(`[${log.timestamp}] [${log.level.toUpperCase()}] ${log.message}`);
    }

    const context = contextParts.join('\n');
    logger.debug(`Root cause context: ${fingerprints.size} patterns from ${errorLogs.length} logs (${context.length} chars)`);
    return context;
  }

  /**
   * Format classification entries for the LLM prompt.
   */
  _formatForLLM(entries, type) {
    const parts = [];
    parts.push(`=== LOG ENTRIES FOR ${type.toUpperCase()} ===`);
    parts.push(`Total entries: ${entries.length}`);
    parts.push('');

    for (const entry of entries) {
      parts.push(`[ID: ${entry.id}] [${entry.timestamp || 'N/A'}] [${entry.level}] ${entry.message}`);
      if (entry.neighborContext && entry.neighborContext.length > 0) {
        parts.push(`  Surrounding context:`);
        entry.neighborContext.forEach((n) => parts.push(`    ${n}`));
      }
      parts.push('');
    }

    return parts.join('\n');
  }
}

module.exports = new ContextSelector();
