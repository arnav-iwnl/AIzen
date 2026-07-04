const crypto = require('crypto');

/**
 * Generate a short fingerprint hash from a string.
 * Used to group identical/similar log messages.
 */
function generateFingerprint(level, message) {
  // Normalize: remove PIDs, slot numbers, child IDs, timestamps, paths — keep the pattern
  const normalized = message
    .replace(/\b\d{3,}\b/g, 'N')        // Replace long numbers (PIDs, child IDs) with N
    .replace(/slot\s+\d+/g, 'slot N')    // Normalize slot numbers
    .replace(/child\s+\d+/g, 'child N')  // Normalize child IDs
    .replace(/state\s+\d+/g, 'state N')  // Normalize state numbers
    .replace(/\/[\w\/\.\-]+/g, 'PATH')   // Normalize file paths
    .trim();

  const input = `${level}:${normalized}`;
  return crypto.createHash('sha256').update(input).digest('hex').substring(0, 12);
}

/**
 * Parse Apache log timestamp string to ISO 8601.
 * Input:  "Sun Dec 04 04:47:44 2005"
 * Output: "2005-12-04T04:47:44.000Z"
 */
function parseApacheTimestamp(timestampStr) {
  const date = new Date(timestampStr);
  if (isNaN(date.getTime())) {
    return null;
  }
  return date.toISOString();
}

/**
 * Create a time bucket key from a Date for grouping logs by time windows.
 * Groups into N-minute buckets.
 */
function getTimeBucketKey(isoTimestamp, bucketMinutes = 15) {
  const date = new Date(isoTimestamp);
  const minutes = date.getMinutes();
  const bucketMinute = Math.floor(minutes / bucketMinutes) * bucketMinutes;
  date.setMinutes(bucketMinute, 0, 0);
  return date.toISOString();
}

/**
 * Create an hourly bucket key for coarser time grouping.
 */
function getHourlyBucketKey(isoTimestamp) {
  const date = new Date(isoTimestamp);
  date.setMinutes(0, 0, 0);
  return date.toISOString();
}

/**
 * Group an array of items by a key function.
 */
function groupBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(item);
  }
  return groups;
}

/**
 * Pick a stratified sample from an array.
 * Returns up to maxCount items, evenly distributed.
 */
function stratifiedSample(items, maxCount) {
  if (items.length <= maxCount) return [...items];

  const step = items.length / maxCount;
  const sampled = [];
  for (let i = 0; i < maxCount; i++) {
    sampled.push(items[Math.floor(i * step)]);
  }
  return sampled;
}

/**
 * Format milliseconds to a human-readable duration.
 */
function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

module.exports = {
  generateFingerprint,
  parseApacheTimestamp,
  getTimeBucketKey,
  getHourlyBucketKey,
  groupBy,
  stratifiedSample,
  formatDuration,
};
