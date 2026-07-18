const aiClient = require('../ai/aiClient');
const promptTemplates = require('../ai/promptTemplates');
const responseParser = require('../ai/responseParser');
const contextSelector = require('./contextSelector');
const logStore = require('../store/logStore');
const logger = require('../utils/logger');

/**
 * Timeline Service — Feature 2
 * Generates an incident timeline from multiple log entries.
 * The AI intelligently summarizes related logs into meaningful timeline entries.
 */
class TimelineService {
  /**
   * Generate an incident timeline.
   * @param {Object} options - { startTime, endTime, focus, maxEvents }
   * @returns {Object} Timeline result
   */
  async generateTimeline(options = {}) {
    const startTime = Date.now();

    if (!logStore.isLoaded) {
      throw new Error('No logs loaded. Please upload a log file first.');
    }

    logger.info('Generating incident timeline via Map-Reduce', { options });

    // Step 1: Prepare batches of patterns
    const allDeduped = logStore.getDeduped();
    let targetPatterns = options.focus === 'errors' 
      ? allDeduped.filter((d) => d.level === 'error' || d.level === 'crit' || d.level === 'warn')
      : allDeduped;

    const batchSize = require('../config/app.config').logProcessing.timelineBatchSize || 40;
    const batches = [];
    for (let i = 0; i < targetPatterns.length; i += batchSize) {
      batches.push(targetPatterns.slice(i, i + batchSize));
    }

    if (batches.length === 0) {
      batches.push([]); // Handle empty case gracefully
    }

    logger.debug(`Processing ${batches.length} timeline chunks concurrently...`);
    
    const aggregatedUsage = { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 };
    let allEvents = [];
    let summaries = [];

    // Step 2: Map - Process all chunks concurrently
    const batchPromises = batches.map(async (batch, batchIdx) => {
      // Build context for this specific chunk (disable capping inside selector)
      const context = contextSelector.buildTimelineContext({
        startTime: options.startTime,
        endTime: options.endTime,
        focus: options.focus || 'errors',
        primaryPatterns: batch,
        disableCapping: true,
      });

      const systemPrompt = promptTemplates.timeline.system;
      const userPrompt = promptTemplates.timeline.buildUserPrompt(context, {
        focus: options.focus,
        maxEvents: Math.max(3, Math.floor((options.maxEvents || 20) / batches.length)),
      });

      const aiResponse = await aiClient.complete(systemPrompt, userPrompt, { model: options.model });
      const result = responseParser.parseTimeline(aiResponse.text);

      return {
        events: result.timeline,
        summary: result.overallSummary,
        usage: aiResponse.usage || {}
      };
    });

    const completedBatches = await Promise.all(batchPromises);

    // Step 3: Reduce - Merge results
    for (const completed of completedBatches) {
      allEvents.push(...completed.events);
      if (completed.summary) summaries.push(completed.summary);
      
      aggregatedUsage.promptTokenCount += (completed.usage.promptTokenCount || 0);
      aggregatedUsage.candidatesTokenCount += (completed.usage.candidatesTokenCount || 0);
      aggregatedUsage.totalTokenCount += (completed.usage.totalTokenCount || 0);
    }

    // Sort all merged events chronologically
    allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // Cap total events if requested
    if (options.maxEvents && allEvents.length > options.maxEvents) {
      allEvents = allEvents.slice(0, options.maxEvents);
    }

    const enrichedTimeline = allEvents.map((event, index) => ({
      sequence: index + 1,
      ...event,
    }));

    const processingTime = Date.now() - startTime;

    return {
      timeline: enrichedTimeline,
      overallSummary: summaries.join('\n\n'),
      metadata: {
        totalLogsAnalyzed: logStore.stats.totalLogs,
        uniquePatternsUsed: logStore.stats.uniquePatterns,
        timeRange: logStore.stats.timeRange,
        focus: options.focus || 'all',
        eventsGenerated: enrichedTimeline.length,
      },
      processingTimeMs: processingTime,
      usage: aggregatedUsage,
    };
  }
}

module.exports = new TimelineService();
