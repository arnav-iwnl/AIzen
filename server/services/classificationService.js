const aiClient = require('../ai/aiClient');
const promptTemplates = require('../ai/promptTemplates');
const responseParser = require('../ai/responseParser');
const contextSelector = require('./contextSelector');
const logStore = require('../store/logStore');
const logger = require('../utils/logger');
const config = require('../config/app.config');

/**
 * Classification Service — Feature 1
 * Classifies ALL deduplicated Apache log patterns into operational categories.
 * Returns per-pattern classifications plus a full category distribution
 * weighted by occurrence counts (for pie chart visualization).
 */
class ClassificationService {
  /**
   * Classify log entries.
   * When no specific logs are provided, classifies ALL deduplicated patterns
   * from the LogStore for comprehensive coverage.
   *
   * @param {string|string[]} logs - Raw log lines or array of log lines (optional)
   * @returns {Object} Classification results with categoryDistribution
   */
  async classify(logs, options = {}) {
    const startTime = Date.now();

    // If no logs provided, classify ALL deduplicated patterns from the LogStore
    if (!logs || (Array.isArray(logs) && logs.length === 0)) {
      if (!logStore.isLoaded) {
        throw new Error('No logs provided and no logs are currently loaded in the store.');
      }
      return this._classifyAllPatterns(startTime, options);
    }

    // Normalize input — accept single string or array
    const logLines = Array.isArray(logs) ? logs : [logs];
    logger.info(`Classifying ${logLines.length} specific log entries`);

    // Parse the incoming log lines
    const preprocessor = require('./preprocessor');
    let parsedLogs = preprocessor.parseLines(logLines);
    if (parsedLogs.length === 0) {
      parsedLogs = logLines.map((line, i) => ({
        id: `input_${i + 1}`,
        raw: line,
        timestamp: null,
        level: 'unknown',
        message: line,
        fingerprint: `input_${i}`,
        lineNumber: i + 1,
      }));
    }

    // Wrap them as "patterns" with occurrence count 1
    const patterns = parsedLogs.map(log => ({
      ...log,
      occurrenceCount: 1,
      firstSeen: log.timestamp,
      lastSeen: log.timestamp,
    }));

    return this._classifyPatterns(patterns, startTime, options);
  }

  /**
   * Classify ALL deduplicated patterns from the LogStore.
   * This gives full coverage of the entire log dataset.
   */
  async _classifyAllPatterns(startTime, options) {
    const allPatterns = logStore.getDeduped();
    logger.info(`Classifying ALL ${allPatterns.length} deduplicated patterns (representing ${logStore.stats.totalLogs} total logs)`);
    return this._classifyPatterns(allPatterns, startTime, options);
  }

  /**
   * Core classification logic — processes patterns through the LLM in batches.
   *
   * @param {Object[]} patterns - Deduplicated patterns with occurrenceCount
   * @param {number} startTime - Start time for performance tracking
   * @returns {Object} Full classification results
   */
  async _classifyPatterns(patterns, startTime, options = {}) {
    const batchSize = config.logProcessing.classificationBatchSize;
    const batches = [];
    for (let i = 0; i < patterns.length; i += batchSize) {
      batches.push(patterns.slice(i, i + batchSize));
    }

    const allResults = [];
    const aggregatedUsage = { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 };

    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      logger.debug(`Processing classification batch ${batchIdx + 1}/${batches.length} (${batch.length} patterns)`);

      // Build context from deduplicated patterns
      const context = contextSelector.buildClassificationContext(batch);

      // Build prompts
      const systemPrompt = promptTemplates.classification.system;
      const userPrompt = promptTemplates.classification.buildUserPrompt(context);

      // Call LLM
      const aiResponse = await aiClient.complete(systemPrompt, userPrompt, { model: options.model });
      const rawResponse = aiResponse.text;
      
      // Aggregate token usage
      if (aiResponse.usage) {
        aggregatedUsage.promptTokenCount += (aiResponse.usage.promptTokenCount || 0);
        aggregatedUsage.candidatesTokenCount += (aiResponse.usage.candidatesTokenCount || 0);
        aggregatedUsage.totalTokenCount += (aiResponse.usage.totalTokenCount || 0);
      }

      // Parse and validate response
      const batchResults = responseParser.parseClassification(rawResponse);

      // Merge results, mapping back to original patterns
      for (let i = 0; i < batch.length; i++) {
        const pattern = batch[i];
        const result = batchResults.find((r) => r.id === pattern.id) || batchResults[i];

        allResults.push({
          logId: pattern.id,
          originalLog: pattern.raw,
          timestamp: pattern.timestamp,
          sourceLevel: pattern.level,
          occurrenceCount: pattern.occurrenceCount,
          firstSeen: pattern.firstSeen || null,
          lastSeen: pattern.lastSeen || null,
          classification: {
            category: result ? result.category : 'Unknown',
            confidence: result ? result.confidence : 0,
            severity: result ? result.severity : 'medium',
            explanation: result ? result.explanation : 'Classification unavailable',
            insight: result ? result.insight : '',
          },
        });
      }
    }

    const processingTime = Date.now() - startTime;

    return {
      totalClassified: allResults.length,
      totalLogsRepresented: allResults.reduce((sum, r) => sum + (r.occurrenceCount || 1), 0),
      batchesProcessed: batches.length,
      classifications: allResults,
      summary: this._buildSummary(allResults),
      categoryDistribution: this._buildCategoryDistribution(allResults),
      processingTimeMs: processingTime,
      usage: aggregatedUsage,
    };
  }

  /**
   * Build a summary of classification results.
   */
  _buildSummary(results) {
    const categoryCounts = {};
    let totalConfidence = 0;

    for (const result of results) {
      const cat = result.classification.category;
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      totalConfidence += result.classification.confidence;
    }

    return {
      categoryCounts,
      averageConfidence: results.length > 0 ? Math.round(totalConfidence / results.length) : 0,
      dominantCategory: Object.entries(categoryCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'Unknown',
    };
  }

  /**
   * Build category distribution weighted by occurrence count.
   * This gives the TRUE distribution across all logs, not just unique patterns.
   * Powers the pie chart on the frontend.
   *
   * @returns {Object[]} Array of { category, patternCount, logCount, percentage, severity }
   */
  _buildCategoryDistribution(results) {
    const totalLogs = results.reduce((sum, r) => sum + (r.occurrenceCount || 1), 0);
    const categoryMap = {};

    for (const result of results) {
      const cat = result.classification.category;
      if (!categoryMap[cat]) {
        categoryMap[cat] = {
          category: cat,
          patternCount: 0,
          logCount: 0,
          severities: {},
          insights: [],
        };
      }
      categoryMap[cat].patternCount += 1;
      categoryMap[cat].logCount += (result.occurrenceCount || 1);

      // Track severity distribution within category
      const sev = result.classification.severity || 'medium';
      categoryMap[cat].severities[sev] = (categoryMap[cat].severities[sev] || 0) + (result.occurrenceCount || 1);

      // Collect insights
      if (result.classification.insight) {
        categoryMap[cat].insights.push(result.classification.insight);
      }
    }

    // Convert to sorted array with percentages
    return Object.values(categoryMap)
      .map(cat => ({
        category: cat.category,
        patternCount: cat.patternCount,
        logCount: cat.logCount,
        percentage: totalLogs > 0 ? Math.round((cat.logCount / totalLogs) * 1000) / 10 : 0,
        dominantSeverity: Object.entries(cat.severities).sort((a, b) => b[1] - a[1])[0]?.[0] || 'medium',
        severityBreakdown: cat.severities,
        insight: cat.insights[0] || '', // Use the first insight as representative
      }))
      .sort((a, b) => b.logCount - a.logCount);
  }
}

module.exports = new ClassificationService();
