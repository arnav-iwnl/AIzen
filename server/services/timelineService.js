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

    logger.info('Generating incident timeline', { options });

    // Step 1: Build context using context selector (handles dedup + windowing)
    const context = contextSelector.buildTimelineContext({
      startTime: options.startTime,
      endTime: options.endTime,
      focus: options.focus || 'errors',
    });

    // Step 2: Build prompts
    const systemPrompt = promptTemplates.timeline.system;
    const userPrompt = promptTemplates.timeline.buildUserPrompt(context, {
      focus: options.focus,
      maxEvents: options.maxEvents || 20,
    });

    // Step 3: Call LLM
    const aiResponse = await aiClient.complete(systemPrompt, userPrompt, { model: options.model });
    const rawResponse = aiResponse.text;

    // Step 4: Parse and validate response
    const result = responseParser.parseTimeline(rawResponse);

    // Step 5: Enrich timeline with log store data
    const enrichedTimeline = result.timeline.map((event, index) => ({
      sequence: index + 1,
      ...event,
    }));

    const processingTime = Date.now() - startTime;

    return {
      timeline: enrichedTimeline,
      overallSummary: result.overallSummary,
      metadata: {
        totalLogsAnalyzed: logStore.stats.totalLogs,
        uniquePatternsUsed: logStore.stats.uniquePatterns,
        timeRange: logStore.stats.timeRange,
        focus: options.focus || 'all',
        eventsGenerated: enrichedTimeline.length,
      },
      processingTimeMs: processingTime,
      usage: aiResponse.usage || { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }
}

module.exports = new TimelineService();
