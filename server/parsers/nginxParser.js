const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Nginx Error Log Parser
 * Parses lines like:
 * 2024/01/15 10:30:00 [error] 1234#0: *1 connect() failed (111: Connection refused)
 * while connecting to upstream, client: 1.2.3.4, server: example.com
 *
 * Also accepts the same combined access-log format as Apache access logs
 * (handled separately by apacheAccessLogParser).
 */
class NginxLogParser extends BaseParser {
  constructor() {
    super('nginx');
    // Group 1: "2024/01/15 10:30:00"
    // Group 2: level (error/warn/info/notice/crit/emerg/alert)
    // Group 3: "1234#0: *1 " prefix (pid#tid and connection number) — optional
    // Group 4: message
    this.lineRegex = /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(?:\d+#\d+:)?\s*(?:\*\d+\s+)?(.+)$/;
  }

  parseTimestamp(timestampStr) {
    // "2024/01/15 10:30:00" → "2024-01-15T10:30:00"
    const iso = timestampStr.replace(/\//g, '-').replace(' ', 'T');
    const date = new Date(iso);
    return isNaN(date.getTime()) ? null : date.toISOString();
  }

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
    const timestamp = this.parseTimestamp(timestampStr);
    const fingerprint = generateFingerprint(level.toLowerCase(), message);

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

  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 5);
    if (lines.length === 0) return false;

    const matchCount = lines.filter((line) => this.lineRegex.test(line)).length;
    return matchCount / lines.length >= 0.5;
  }
}

module.exports = NginxLogParser;
