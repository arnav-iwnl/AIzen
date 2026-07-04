const express = require('express');
const { validate } = require('../middleware/requestValidator');
const { aiRateLimiter } = require('../middleware/rateLimiter');
const classificationService = require('../services/classificationService');
const timelineService = require('../services/timelineService');
const rootCauseService = require('../services/rootCauseService');
const logStore = require('../store/logStore');
const aiClient = require('../ai/aiClient');
const logger = require('../utils/logger');

const router = express.Router();

// Apply AI rate limiter to all AI routes
router.use(aiRateLimiter);

/**
 * POST /api/ai/log-classification
 * Feature 1: Classify Apache log entries into meaningful categories.
 */
router.post(
  '/log-classification',
  validate('logClassification'),
  async (req, res, next) => {
    try {
      if (!aiClient.isConfigured()) {
        return res.error('AI service is not configured. Please set NVIDIA_NIM_API_KEY in .env', 503);
      }

      const options = req.validatedBody || {};
      const result = await classificationService.classify(options.logs, options);

      return res.success(result, 'Log classification completed successfully');
    } catch (error) {
      logger.error('Classification failed', { error: error.message });
      next(error);
    }
  }
);

/**
 * POST /api/ai/incident-timeline
 * Feature 2: Generate an incident timeline from log entries.
 */
router.post(
  '/incident-timeline',
  validate('incidentTimeline'),
  async (req, res, next) => {
    try {
      if (!aiClient.isConfigured()) {
        return res.error('AI service is not configured. Please set NVIDIA_NIM_API_KEY in .env', 503);
      }

      if (!logStore.isLoaded) {
        return res.error('No logs loaded. Please upload or load a log file first.', 400);
      }

      const options = req.validatedBody || {};
      const result = await timelineService.generateTimeline(options);

      return res.success(result, 'Incident timeline generated successfully');
    } catch (error) {
      logger.error('Timeline generation failed', { error: error.message });
      next(error);
    }
  }
);

/**
 * POST /api/ai/root-cause-analysis
 * Feature 3: Perform root cause analysis on log entries.
 */
router.post(
  '/root-cause-analysis',
  validate('rootCauseAnalysis'),
  async (req, res, next) => {
    try {
      if (!aiClient.isConfigured()) {
        return res.error('AI service is not configured. Please set NVIDIA_NIM_API_KEY in .env', 503);
      }

      if (!logStore.isLoaded) {
        return res.error('No logs loaded. Please upload or load a log file first.', 400);
      }

      const options = req.validatedBody || {};
      const result = await rootCauseService.analyze(options);

      return res.success(result, 'Root cause analysis completed successfully');
    } catch (error) {
      logger.error('Root cause analysis failed', { error: error.message });
      next(error);
    }
  }
);

/**
 * GET /api/ai/status
 * Check AI service status and configuration.
 */
router.get('/status', (req, res) => {
  return res.success({
    ai: aiClient.getInfo(),
    logsLoaded: logStore.isLoaded,
    logStats: logStore.isLoaded ? logStore.getStats() : null,
  }, 'AI service status retrieved');
});

module.exports = router;
