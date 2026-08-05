const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * JSON Log Parser
 * Parses one JSON object per line (common for structured logging:
 * Bunyan, Winston JSON, ELK, Datadog-forwarded, etc.).
 *
 * Recognized fields:
 * - timestamp: timestamp | @timestamp | ts | time | datetime
 * - level:     level | severity | log.level | @level
 * - message:   message | msg | log | message body (nested objects stringified)
 */
class JsonLogParser extends BaseParser {
  constructor() {
    super('json');
  }

  parseTimestamp(value) {
    if (value == null) return null;
    if (typeof value === 'number') {
      // Unix seconds or millis
      const ms = value < 1e12 ? value * 1000 : value;
      const date = new Date(ms);
      return isNaN(date.getTime()) ? null : date.toISOString();
    }
    const date = new Date(value);
    return isNaN(date.getTime()) ? null : date.toISOString();
  }

  parseLine(line, lineNumber) {
    const trimmed = line.trim();
    if (!trimmed) return null;

    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch {
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

    const timestamp =
      this.parseTimestamp(obj.timestamp) ||
      this.parseTimestamp(obj['@timestamp']) ||
      this.parseTimestamp(obj.ts) ||
      this.parseTimestamp(obj.time) ||
      this.parseTimestamp(obj.datetime) ||
      this.parseTimestamp(obj.date);

    const rawLevel = obj.level || obj.severity || obj['@level'] || (obj.log && obj.log.level) || '';
    const level = String(rawLevel).toLowerCase();

    let message = obj.message || obj.msg || obj.log || '';
    if (typeof message !== 'string') {
      message = typeof message === 'object' ? JSON.stringify(message) : String(message);
    }
    if (!message && obj.error) {
      message = typeof obj.error === 'string' ? obj.error : JSON.stringify(obj.error);
    }

    const fingerprint = generateFingerprint(level || 'info', message || trimmed);

    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp,
      level: level || 'info',
      message: message || trimmed,
      fingerprint,
      lineNumber,
      parsedAt: new Date().toISOString(),
    };
  }

  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 5);
    if (lines.length === 0) return false;

    const jsonCount = lines.filter((line) => {
      try {
        const parsed = JSON.parse(line);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed);
      } catch {
        return false;
      }
    }).length;
    return jsonCount / lines.length >= 0.5;
  }
}

module.exports = JsonLogParser;
