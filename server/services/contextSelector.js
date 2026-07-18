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
   * Detect patterns indicating security issues (SQLi, XSS, Path Traversal, etc.)
   */
  _detectSecuritySignals(dedupedPatterns) {
    const SECURITY_PATTERNS = [
      { type: 'PATH_TRAVERSAL', regex: /(?:\/etc\/passwd|\.\.\/|\.\.\\|\/proc\/|\/var\/log)/i },
      { type: 'SQL_INJECTION', regex: /(?:['"]?\s*(?:OR|AND|UNION)\s+\d|SELECT\s+.*FROM|DROP\s+TABLE|--\s*$|%27|%22.*(?:OR|AND))/i },
      { type: 'XSS_PROBE', regex: /(?:<script|javascript:|onerror\s*=|onload\s*=|<xsstag>|domxss|<img\s+src)/i },
      { type: 'ADMIN_BRUTE_FORCE', regex: /(?:\/administrator\/|\/admin\/|\/wp-admin|\/login).*(?:POST|5\d{2})/i },
      { type: 'DIRECTORY_FORBIDDEN', regex: /(?:Directory index forbidden|forbidden by rule)/i },
      { type: 'CREDENTIAL_PROBE', regex: /(?:task=user\.login|task=registration|\/wp-login|auth|token)/i },
      { type: 'SCANNER_SIGNATURE', regex: /(?:acunetix|nikto|sqlmap|nmap|wvstest|dirbuster)/i },
    ];

    const signals = [];
    const seenFingerprints = new Set();

    for (const pattern of dedupedPatterns) {
      const textToCheck = `${pattern.raw || ''} ${pattern.message || ''}`;
      for (const { type, regex } of SECURITY_PATTERNS) {
        if (regex.test(textToCheck) && !seenFingerprints.has(`${type}:${pattern.fingerprint}`)) {
          seenFingerprints.add(`${type}:${pattern.fingerprint}`);
          signals.push({
            type,
            level: pattern.level,
            message: pattern.message,
            raw: pattern.raw || pattern.message,
            occurrenceCount: pattern.occurrenceCount || 1,
            timestamp: pattern.timestamp,
            fingerprint: pattern.fingerprint,
          });
        }
      }
    }
    return signals;
  }

  /**
   * Build chronological incident narrative windows.
   */
  _buildIncidentNarrative(logs) {
    const WINDOW_BEFORE = 3;
    const WINDOW_AFTER = 2;
    const MAX_NARRATIVE_WINDOWS = 6;

    const errorLogs = logs.filter(l => l.level === 'error' || l.level === 'crit');
    if (errorLogs.length === 0) return [];

    const sampledErrors = stratifiedSample(errorLogs, MAX_NARRATIVE_WINDOWS);
    const windows = [];

    for (const errLog of sampledErrors) {
      const idx = logs.findIndex(l => l.id === errLog.id);
      if (idx === -1) continue;

      const startIdx = Math.max(0, idx - WINDOW_BEFORE);
      const endIdx = Math.min(logs.length - 1, idx + WINDOW_AFTER);
      
      const windowLogs = logs.slice(startIdx, endIdx + 1).map(l => ({
        timestamp: l.timestamp,
        level: l.level,
        message: l.message,
        isError: l.id === errLog.id
      }));

      windows.push({
        errorTimestamp: errLog.timestamp,
        logs: windowLogs
      });
    }

    return windows;
  }

  /**
   * Build escalation chains (info -> warning -> error)
   */
  _buildEscalationChains(logs) {
    const chains = [];
    let currentChain = [];

    for (let i = 0; i < logs.length; i++) {
      const log = logs[i];
      
      if (log.level === 'info' || log.level === 'notice') {
        currentChain.push(log);
        if (currentChain.length > 5) currentChain.shift();
      } else if (log.level === 'warn') {
        currentChain.push(log);
        if (currentChain.length > 5) currentChain.shift();
      } else if (log.level === 'error' || log.level === 'crit') {
        if (currentChain.some(l => l.level === 'warn')) {
          chains.push({
            chainCount: 1,
            precedingEvents: [...currentChain],
            errorLog: log
          });
        }
        currentChain = []; // reset after error
      }
    }
    
    // Group and deduplicate similar chains
    const dedupedChains = [];
    const seen = new Set();
    for (const chain of chains) {
      const fp = chain.errorLog.fingerprint || chain.errorLog.message;
      const existing = dedupedChains.find(c => c.fp === fp);
      if (existing) {
        existing.chainCount++;
      } else {
        dedupedChains.push({ ...chain, fp });
      }
    }

    return dedupedChains.slice(0, 10);
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
    let logs = options.logs || logStore.logs;

    if (options.startTime && options.endTime && !options.logs) {
      logs = logStore.getByTimeRange(options.startTime, options.endTime);
    }

    const allDeduped = logStore.getDeduped();
    let primaryPatterns = options.primaryPatterns;

    if (!primaryPatterns) {
      const errorDeduped = allDeduped.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'warn');
      primaryPatterns = (options.focus === 'errors') ? errorDeduped : allDeduped;
    }

    const securitySignals = options.securitySignals || this._detectSecuritySignals(allDeduped);
    const escalationChains = options.escalationChains || this._buildEscalationChains(logs);
    const incidentNarrative = options.incidentNarrative || this._buildIncidentNarrative(logs);

    const MAX_PRIMARY_PATTERNS = options.maxPatterns || 40;
    if (!options.disableCapping && primaryPatterns.length > MAX_PRIMARY_PATTERNS) {
      const criticalPatterns = primaryPatterns.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'critical');
      const warnPatterns = primaryPatterns.filter((d) => d.level === 'warn' || d.level === 'warning');
      const otherPatterns = primaryPatterns.filter((d) => !['error', 'crit', 'critical', 'warn', 'warning'].includes(d.level));

      const cappedCritical = criticalPatterns.sort((a, b) => b.occurrenceCount - a.occurrenceCount).slice(0, 25);
      const remainingSlots = MAX_PRIMARY_PATTERNS - cappedCritical.length;
      const cappedWarn = warnPatterns.sort((a, b) => b.occurrenceCount - a.occurrenceCount).slice(0, Math.ceil(remainingSlots * 0.7));
      const cappedOther = otherPatterns.sort((a, b) => b.occurrenceCount - a.occurrenceCount).slice(0, Math.max(0, remainingSlots - cappedWarn.length));

      primaryPatterns = [...cappedCritical, ...cappedWarn, ...cappedOther];
    }

    const byHour = groupBy(primaryPatterns, (log) => {
      if (!log.timestamp) return 'unknown-time';
      const date = new Date(log.timestamp);
      return `${date.toISOString().substring(0, 13)}:00`;
    });

    const contextParts = [];
    contextParts.push(`=== LOG DATASET SUMMARY ===`);
    contextParts.push(`Total logs in file: ${logStore.stats.totalLogs}`);
    contextParts.push(`Unique log patterns: ${allDeduped.length}`);
    contextParts.push(`Error/Warning patterns: ${primaryPatterns.length}`);
    contextParts.push(`Time range: ${logStore.stats.timeRange.start} to ${logStore.stats.timeRange.end}`);
    contextParts.push(`Levels breakdown: ${JSON.stringify(logStore.stats.countByLevel)}`);
    contextParts.push('');

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

    if (securitySignals.length > 0) {
      contextParts.push('\n=== SECURITY SIGNALS (Critical Context) ===');
      for (const signal of securitySignals) {
        contextParts.push(`[${signal.type}] [${signal.level.toUpperCase()}] ${signal.message} | x${signal.occurrenceCount}`);
      }
    }

    if (escalationChains.length > 0) {
      contextParts.push('\n=== INCIDENT ESCALATION CHAINS ===');
      for (let idx = 0; idx < escalationChains.length; idx++) {
        const chain = escalationChains[idx];
        contextParts.push(`--- Chain ${idx + 1} (x${chain.chainCount}) ---`);
        for (const prev of chain.precedingEvents) {
          contextParts.push(`  [${prev.level.toUpperCase()}] ${prev.message}`);
        }
        contextParts.push(`  → [${chain.errorLog.level.toUpperCase()}] ${chain.errorLog.message}`);
      }
    }

    if (incidentNarrative.length > 0) {
      contextParts.push('\n=== CHRONOLOGICAL INCIDENT NARRATIVE ===');
      for (const window of incidentNarrative) {
        contextParts.push(`--- Incident at ${window.errorTimestamp} ---`);
        for (const log of window.logs) {
          const marker = log.isError ? '>>>' : '   ';
          contextParts.push(`${marker} [${log.level.toUpperCase()}] ${log.message}`);
        }
      }
    }

    if (!options.primaryPatterns && logStore.getDeduped().length > 0) {
      contextParts.push('\n=== SUPPLEMENTARY: TOP NON-ERROR PATTERNS ===');
      const nonError = logStore.getDeduped().filter(d => d.level !== 'error' && d.level !== 'warn' && d.level !== 'crit');
      const topNonError = nonError.sort((a, b) => b.occurrenceCount - a.occurrenceCount).slice(0, 10);
      for (const entry of topNonError) {
        contextParts.push(`[${entry.level.toUpperCase()}] ${entry.message} | x${entry.occurrenceCount}`);
      }
    }

    return contextParts.join('\n');
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

    // Use pre-batched target patterns if provided by Map-Reduce (rootCauseService)
    if (options.primaryPatterns) {
      // Find raw logs associated with these specific deduped patterns
      const targetIds = options.primaryPatterns.map(p => p.id);
      const contextLogs = [];
      const targetLogs = logStore.getDeduped().filter(d => targetIds.includes(d.id));
      
      for (const pattern of targetLogs) {
        // Just find the first occurrence in the raw logs to get context window
        const foundLogs = logStore.logs.filter(l => l.fingerprint === pattern.fingerprint);
        if (foundLogs.length > 0) {
           const log = foundLogs[0];
           const idx = logStore.getIndexById(log.id);
           if (idx >= 0) {
             contextLogs.push(...logStore.getWindow(idx, 5));
           }
        }
      }
      const seen = new Set();
      errorLogs = contextLogs.filter((l) => {
        if (seen.has(l.id)) return false;
        seen.add(l.id);
        return true;
      });
    } else if (options.logIds && options.logIds.length > 0) {
      const targetLogs = logStore.getByIds(options.logIds);
      const contextLogs = [];
      for (const log of targetLogs) {
        const idx = logStore.getIndexById(log.id);
        if (idx >= 0) {
          const window = logStore.getWindow(idx, 5);
          contextLogs.push(...window);
        }
      }
      const seen = new Set();
      errorLogs = contextLogs.filter((l) => {
        if (seen.has(l.id)) return false;
        seen.add(l.id);
        return true;
      });
    } else if (options.timeRange) {
      errorLogs = logStore.getByTimeRange(options.timeRange.start, options.timeRange.end);
    } else if (options.symptom) {
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
      errorLogs = logStore.getErrorsWithContext(5);
    }

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

    // ── CAP PATTERN COUNT ──────────────────────────────────────────────
    const MAX_RCA_PATTERNS = options.maxPatterns || 30;
    let finalFingerprints = Array.from(fingerprints.values());
    
    if (!options.disableCapping && finalFingerprints.length > MAX_RCA_PATTERNS) {
      finalFingerprints = finalFingerprints
        .sort((a, b) => b.count - a.count)
        .slice(0, MAX_RCA_PATTERNS);
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
    for (const group of finalFingerprints) {
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
