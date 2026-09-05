const express = require('express');
const datasetDemoService = require('../demo/datasetDemoService');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/demo-dataset/sources
 * List the available data sources (logs + v2 training datasets).
 */
router.get('/sources', (req, res) => {
  return res.success(datasetDemoService.getSources(), 'Dataset demo sources retrieved');
});

/**
 * GET /api/demo-dataset/state
 * Current stream status.
 */
router.get('/state', (req, res) => {
  return res.success(datasetDemoService.getStreamState(), 'Dataset demo stream state');
});

/**
 * POST /api/demo-dataset/trigger
 * Fire `count` sniffed lines from a source into the realtime hub.
 * Body: { count?, source? }
 */
router.post('/trigger', async (req, res, next) => {
  try {
    const { count = 50 } = req.body || {};
    const result = await datasetDemoService.trigger(count);
    return res.success(result, `Fired ${result.generated} lines (${result.attacks} attacks)`);
  } catch (error) {
    logger.error('Dataset demo trigger failed', { error: error.message });
    next(error);
  }
});

/**
 * POST /api/demo-dataset/stream
 * Start/stop the auto-stream.
 * Body: { running: boolean, source?: string, rate?: number }
 */
router.post('/stream', async (req, res, next) => {
  try {
    const { running = false, source, rate } = req.body || {};
    const state = running
      ? await datasetDemoService.startStream({ source, rate })
      : datasetDemoService.stopStream();
    return res.success(state, running ? 'Dataset stream started' : 'Dataset stream stopped');
  } catch (error) {
    logger.error('Dataset demo stream control failed', { error: error.message });
    next(error);
  }
});

module.exports = router;
