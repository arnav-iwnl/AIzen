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

/**
 * General rate limiter for all endpoints (more permissive).
 */
const generalRateLimiter = rateLimit({
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

module.exports = { aiRateLimiter, generalRateLimiter };
