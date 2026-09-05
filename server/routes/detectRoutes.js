const express = require('express');
const incidentService = require('../services/incidentService');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * POST /api/detect/incidents
 * Run local incident detection (error bursts, novelty, escalation chains).
 * No LLM involved — sub-second even on 100k+ lines.
 */
router.post('/incidents', async (req, res, next) => {
  try {
    const options = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await incidentService.detect(options);
    return res.success(result, `Detected ${result.incidents.length} incidents`);
  } catch (error) {
    logger.error('Incident detection failed', { error: error.message });
    next(error);
  }
});

module.exports = router;
