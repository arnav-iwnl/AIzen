/**
 * Request Logger Middleware for Vulnerable Site
 * 
 * Logs every HTTP request in Apache access log format and forwards
 * the log entry to the AIzen SIEM backend for real-time breach detection.
 */
const axios = require('axios');

const AIZEN_BACKEND_URL = process.env.AIZEN_BACKEND_URL || 'http://localhost:3000';
const INGEST_ENDPOINT = `${AIZEN_BACKEND_URL}/api/realtime/ingest`;

/**
 * Format a request/response into Apache Combined Log Format
 * Example: 127.0.0.1 - - [03/Sep/2026:10:26:56 +0000] "GET /search?q=test HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
 */
function formatLogLine(req, res, responseTime) {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const timestamp = new Date().toISOString().replace('T', ' ').replace('Z', ' +0000').replace(/\.\d+/, '');
  const method = req.method;
  const url = req.originalUrl || req.url;
  const httpVersion = `HTTP/${req.httpVersion}`;
  const statusCode = res.statusCode;
  const contentLength = res.get('content-length') || 0;
  const userAgent = req.get('user-agent') || '-';
  
  // Apache combined log format: IP - - [timestamp] "method url HTTP/1.1" status size "referer" "user-agent"
  // Omit referer to avoid logging attack payloads from referer header
  return `${ip} - - [${timestamp}] "${method} ${url} HTTP/1.1" ${statusCode} ${contentLength} "-" "${userAgent}"`;
}

/**
 * Format current time in Apache log timestamp format
 * [03/Sep/2026:10:26:56 +0000]
 */
function formatApacheTimestamp(date = new Date()) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = String(date.getDate()).padStart(2, '0');
  const month = months[date.getMonth()];
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${day}/${month}/${year}:${hours}:${minutes}:${seconds} +0000`;
}

/**
 * Forward log line to AIzen backend for real-time breach detection
 * Fire-and-forget: doesn't block the response
 */
async function forwardToAIzen(logLine, source = 'vulnerable-app') {
  try {
    await fetch(`${process.env.AIZEN_BACKEND_URL || 'http://localhost:3000'}/api/realtime/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: logLine, source: 'vulnerable-app' }),
    }).catch(() => {}); // Fire-and-forget, ignore errors
  } catch (err) {
    // Silently ignore - logging shouldn't break the app
  }
}

module.exports = (req, res, next) => {
  const startTime = Date.now();
  
  // Capture the original end method to intercept response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const responseTime = Date.now() - startTime;
    
    // Generate Apache combined log format line
    const logLine = formatLogLine(req, res, responseTime);
    
    // Log to console (for container logs)
    console.log(`[Vulnerable Site] ${logLine}`);
    
    // Forward to AIzen backend (fire-and-forget)
    forwardToAIzen(logLine, 'vulnerable-app');
    
    // Call original end
    res.end = originalEnd;
    return res.end(chunk, encoding);
  };
  
  next();
};