const rateLimit = require('express-rate-limit');
const config = require('../config/app.config');

/**
 * Rate Limiter for AI endpoints.
 * Prevents excessive LLM API calls which could be costly.
 */
const aiRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many AI requests. Please try again later.',
    processingTimeMs: null,
    data: null,
  },
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  },
});

// Liveness probes must not consume the general request budget. Render polls the
// health endpoint itself, the client pings it on a timer, and the long-lived SSE
// stream reconnects every time the free-tier instance spins down and wakes. All
// of that is infrastructure chatter rather than user traffic, and counting it
// meant a client left on a backgrounded tab could burn the whole budget on it
// and then get a 429 on the upload it was actually trying to make.
const SKIP_PATHS = new Set(['/api/health', '/api/health/extended']);

const generalLimit = rateLimit({
  windowMs: 60000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests. Please try again later.',
    processingTimeMs: null,
    data: null,
  },
});

/**
 * General rate limiter for all endpoints (more permissive).
 * Exported under its original name: index.js does app.use(generalRateLimiter).
 */
function generalRateLimiter(req, res, next) {
  if (SKIP_PATHS.has(req.path)) return next();
  return generalLimit(req, res, next);
}

module.exports = { aiRateLimiter, generalRateLimiter };
