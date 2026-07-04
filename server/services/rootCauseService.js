const aiClient = require('../ai/aiClient');
const promptTemplates = require('../ai/promptTemplates');
const responseParser = require('../ai/responseParser');
const contextSelector = require('./contextSelector');
const logStore = require('../store/logStore');
const logger = require('../utils/logger');

/**
 * Root Cause Analysis Service — Feature 3
 * Analyzes related logs and determines the most probable root cause of an incident.
 * Evidence-driven and supported by relevant log entries.
 */
class RootCauseService {
  /**
   * Perform root cause analysis.
   * @param {Object} options - { logIds, timeRange, symptom }
   * @returns {Object} Root cause analysis result
   */
  async analyze(options = {}) {
    const startTime = Date.now();

    if (!logStore.isLoaded) {
      throw new Error('No logs loaded. Please upload a log file first.');
    }

    logger.info('Performing root cause analysis', { options });

    // Step 1: Build context using context selector (error-focused with windows)
    const context = contextSelector.buildRootCauseContext({
      logIds: options.logIds,
      timeRange: options.timeRange,
      symptom: options.symptom,
    });

    // Step 2: Build prompts
    const systemPrompt = promptTemplates.rootCause.system;
    const userPrompt = promptTemplates.rootCause.buildUserPrompt(context, {
      symptom: options.symptom,
    });

    // Step 3: Call LLM
    const aiResponse = await aiClient.complete(systemPrompt, userPrompt, { model: options.model });
    const rawResponse = aiResponse.text;

    // Step 4: Parse and validate response
    const result = responseParser.parseRootCause(rawResponse);

    const processingTime = Date.now() - startTime;

    return {
      analysis: result,
      metadata: {
        totalLogsInDataset: logStore.stats.totalLogs,
        errorLogsAnalyzed: (logStore.getByLevel('error') || []).length,
        uniqueErrorPatterns: logStore.stats.topPatterns.filter((p) => p.level === 'error').length,
        timeRange: logStore.stats.timeRange,
        analysisScope: options.logIds
          ? `${options.logIds.length} specific logs`
          : options.timeRange
            ? `Time range: ${options.timeRange.start} to ${options.timeRange.end}`
            : options.symptom
              ? `Symptom search: "${options.symptom}"`
              : 'All Logs',
      },
      processingTimeMs: processingTime,
      usage: aiResponse.usage || { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }
}

module.exports = new RootCauseService();
