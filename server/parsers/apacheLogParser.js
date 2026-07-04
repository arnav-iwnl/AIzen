const BaseParser = require('./baseParser');
const { generateFingerprint, parseApacheTimestamp } = require('../utils/helpers');

/**
 * Apache Log Parser
 * Parses Apache error/notice log lines in the format:
 * [Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties
 */
class ApacheLogParser extends BaseParser {
  constructor() {
    super('apache');
    // Regex to match Apache log lines:
    // Group 1: Timestamp (e.g., "Sun Dec 04 04:47:44 2005")
    // Group 2: Log level (e.g., "notice", "error", "warn", "crit")
    // Group 3: Message (everything after the level)
    this.lineRegex = /^\[([^\]]+)\]\s+\[(\w+)\]\s+(.+)$/;
  }

  /**
   * Parse a single Apache log line.
   * @param {string} line - Raw log line
   * @param {number} lineNumber - Position in file
   * @returns {Object|null} Structured log entry
   */
  parseLine(line, lineNumber) {
    const trimmed = line.trim();
    if (!trimmed) return null;

    const match = trimmed.match(this.lineRegex);
    if (!match) {
      return {
        id: `log_${String(lineNumber).padStart(5, '0')}`,
        raw: trimmed,
        timestamp: null,
        level: 'unknown',
        message: trimmed,
        fingerprint: generateFingerprint('unknown', trimmed),
        lineNumber,
        parsedAt: new Date().toISOString(),
      };
    }

    const [, timestampStr, level, message] = match;
    const timestamp = parseApacheTimestamp(timestampStr);
    const fingerprint = generateFingerprint(level, message);

    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp,
      level: level.toLowerCase(),
      message: message.trim(),
      fingerprint,
      lineNumber,
      parsedAt: new Date().toISOString(),
    };
  }

  /**
   * Detect if the content looks like Apache logs.
   * Checks if the first few lines match the expected pattern.
   */
  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 5);
    if (lines.length === 0) return false;

    const matchCount = lines.filter((line) => this.lineRegex.test(line)).length;
    return matchCount / lines.length >= 0.5; // At least 50% of sample lines match
  }
}

module.exports = ApacheLogParser;
