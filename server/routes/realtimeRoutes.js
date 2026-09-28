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

/**
 * POST /api/realtime/ingest
 * Receive a raw log line from an external source (e.g., vulnerable site)
 * and feed it through the full SIEM pipeline (rules + v2).
 *
 * `techniques` is optional ground truth: the ATT&CK ids the source says this
 * request exercises (the vulnerable site declares which attack each of its
 * routes models). It is carried through to the event as `expectedTechniques`
 * so the UI can show what the detector found vs what was actually attempted.
 * It never influences classification.
 */
router.post('/ingest', async (req, res) => {
  const { raw, source, techniques } = req.body || {};
  if (!raw) return res.error('raw is required', 400);
  const ev = await realtimeHub.ingestLine(
    raw,
    source || 'external',
    null,
    Array.isArray(techniques) ? techniques.filter((t) => typeof t === 'string').slice(0, 5) : null
  );
  return res.success(ev, 'Ingested');
});

module.exports = router;
