const express = require('express');
const realtimeHub = require('../realtime/realtimeHub');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/realtime/stream
 * Server-Sent Events feed. Sends a snapshot immediately, then live log/alert events.
 */
router.get('/stream', (req, res) => {
  realtimeHub.subscribe(req, res);
});

/**
 * GET /api/realtime/snapshot
 * Recent events + alerts + counters (for late joiners / page refresh).
 */
router.get('/snapshot', (req, res) => {
  return res.success(realtimeHub.getSnapshot(), 'Realtime snapshot retrieved');
});

/**
 * POST /api/realtime/clear
 * Reset the live buffer and counters.
 */
router.post('/clear', (req, res) => {
  realtimeHub.clear();
  return res.success({ cleared: true }, 'Realtime feed cleared');
});

module.exports = router;
