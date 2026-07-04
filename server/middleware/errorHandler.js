const logger = require('../utils/logger');

/**
 * Global Error Handler Middleware
 * Catches all unhandled errors and returns a structured error response.
 * Must be registered LAST in the middleware chain (4 params = error handler).
 */
function errorHandler(err, req, res, _next) {
  const processingTimeMs = req.startTime ? Date.now() - req.startTime : null;

  // Log the error
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Determine status code
  const statusCode = err.statusCode || err.status || 500;

  // Build response
  const response = {
    success: false,
    message: err.isOperational ? err.message : 'Internal server error',
    processingTimeMs,
    data: null,
  };

  // In development, include stack trace
  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(statusCode).json(response);
}

/**
 * Custom operational error class.
 * Use this for known/expected errors (validation failures, not found, etc.)
 */
class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = { errorHandler, AppError };
