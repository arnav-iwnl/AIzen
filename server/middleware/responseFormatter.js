/**
 * Response Formatter Middleware
 * Provides a helper method `res.success()` and `res.error()` that wraps
 * all responses in the standard API format:
 * { success, message, processingTimeMs, data }
 */
function responseFormatter(req, res, next) {
  /**
   * Send a successful response.
   * @param {Object} data - The response payload
   * @param {string} message - Human-readable success message
   * @param {number} statusCode - HTTP status code (default 200)
   */
  res.success = function (data, message = 'Request processed successfully', statusCode = 200) {
    const processingTimeMs = req.startTime ? Date.now() - req.startTime : null;
    return res.status(statusCode).json({
      success: true,
      message,
      processingTimeMs,
      data,
    });
  };

  /**
   * Send an error response.
   * @param {string} message - Human-readable error message
   * @param {number} statusCode - HTTP status code (default 500)
   * @param {Object} details - Additional error details
   */
  res.error = function (message = 'An error occurred', statusCode = 500, details = null) {
    const processingTimeMs = req.startTime ? Date.now() - req.startTime : null;
    const response = {
      success: false,
      message,
      processingTimeMs,
      data: null,
    };
    if (details) {
      response.details = details;
    }
    return res.status(statusCode).json(response);
  };

  next();
}

module.exports = responseFormatter;
