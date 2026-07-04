/**
 * Request Timer Middleware
 * Attaches a start timestamp to each request.
 * Used by responseFormatter to calculate processingTimeMs.
 */
function requestTimer(req, res, next) {
  req.startTime = Date.now();
  next();
}

module.exports = requestTimer;
