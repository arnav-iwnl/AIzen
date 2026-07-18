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

    logger.info('Performing root cause analysis via Map-Reduce', { options });

    // Step 1: Identify target patterns
    const allDeduped = logStore.getDeduped();
    let targetPatterns = [];

    if (options.logIds && options.logIds.length > 0) {
      targetPatterns = allDeduped.filter((d) => options.logIds.includes(d.id));
    } else if (options.symptom) {
      const symptom = options.symptom.toLowerCase();
      targetPatterns = allDeduped.filter((d) =>
        (d.level === 'error' || d.level === 'crit' || d.level === 'warn') &&
        d.message.toLowerCase().includes(symptom)
      );
      if (targetPatterns.length === 0) {
        targetPatterns = allDeduped.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'warn');
      }
    } else {
      targetPatterns = allDeduped.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'warn');
    }

    // Step 2: Batch patterns
    const batchSize = require('../config/app.config').logProcessing.rootCauseBatchSize || 20;
    const batches = [];
    for (let i = 0; i < targetPatterns.length; i += batchSize) {
      batches.push(targetPatterns.slice(i, i + batchSize));
    }

    if (batches.length === 0) {
      batches.push([]);
    }

    logger.debug(`Processing ${batches.length} root cause chunks concurrently...`);
    
    const aggregatedUsage = { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 };
    let chunkResults = [];

    // Step 3: Map - Process all chunks concurrently
    const batchPromises = batches.map(async (batch, batchIdx) => {
      const context = contextSelector.buildRootCauseContext({
        logIds: options.logIds,
        timeRange: options.timeRange,
        symptom: options.symptom,
        primaryPatterns: batch,
        disableCapping: true,
      });

      const systemPrompt = promptTemplates.rootCause.system;
      const userPrompt = promptTemplates.rootCause.buildUserPrompt(context, { symptom: options.symptom });

      const aiResponse = await aiClient.complete(systemPrompt, userPrompt, { model: options.model });
      const result = responseParser.parseRootCause(aiResponse.text);

      return { result, usage: aiResponse.usage || {} };
    });

    const completedBatches = await Promise.all(batchPromises);

    for (const completed of completedBatches) {
      chunkResults.push(completed.result);
      aggregatedUsage.promptTokenCount += (completed.usage.promptTokenCount || 0);
      aggregatedUsage.candidatesTokenCount += (completed.usage.candidatesTokenCount || 0);
      aggregatedUsage.totalTokenCount += (completed.usage.totalTokenCount || 0);
    }

    // Step 4: Reduce - Synthesize if multiple chunks
    let finalResult;
    if (chunkResults.length === 1) {
      finalResult = chunkResults[0];
    } else {
      logger.debug(`Synthesizing ${chunkResults.length} root cause reports into one master report...`);
      const synthesisContext = JSON.stringify(chunkResults, null, 2);
      const synthSystem = promptTemplates.rootCauseSynthesis.system;
      const synthUser = promptTemplates.rootCauseSynthesis.buildUserPrompt(synthesisContext);

      const synthResponse = await aiClient.complete(synthSystem, synthUser, { model: options.model });
      finalResult = responseParser.parseRootCause(synthResponse.text);

      if (synthResponse.usage) {
        aggregatedUsage.promptTokenCount += (synthResponse.usage.promptTokenCount || 0);
        aggregatedUsage.candidatesTokenCount += (synthResponse.usage.candidatesTokenCount || 0);
        aggregatedUsage.totalTokenCount += (synthResponse.usage.totalTokenCount || 0);
      }
    }

    const processingTime = Date.now() - startTime;

    return {
      analysis: finalResult,
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
      usage: aggregatedUsage,
    };
  }
}

module.exports = new RootCauseService();
