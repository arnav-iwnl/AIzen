const express = require('express');
const demoService = require('../demo/demoService');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/demo/actions
 * List available demo actions (drives the /demo UI).
 */
router.get('/actions', (req, res) => {
  return res.success(demoService.getActions(), 'Demo actions retrieved');
});

/**
 * GET /api/demo/stream-state
 * Current auto-stream status.
 */
router.get('/stream-state', (req, res) => {
  return res.success(demoService.getStreamState(), 'Stream state retrieved');
});

/**
 * POST /api/demo/trigger
 * Fire `count` lines of a given action into the realtime feed.
 * Body: { action: string, count: number }
 */
router.post('/trigger', async (req, res, next) => {
  try {
    const { action = 'mixed', count = 1 } = req.body || {};
    const result = await demoService.trigger(action, count);
    return res.success(result, `Fired ${result.generated} ${result.action} log lines`);
  } catch (error) {
    logger.error('Demo trigger failed', { error: error.message });
    next(error);
  }
});

/**
 * POST /api/demo/stream
 * Start/stop the auto-stream.
 * Body: { running: boolean, action?: string, rate?: number }
 */
router.post('/stream', async (req, res, next) => {
  try {
    const { running = false, action, rate } = req.body || {};
    const state = running ? await demoService.startStream({ action, rate }) : demoService.stopStream();
    return res.success(state, running ? 'Auto-stream started' : 'Auto-stream stopped');
  } catch (error) {
    logger.error('Demo stream control failed', { error: error.message });
    next(error);
  }
});

module.exports = router;
