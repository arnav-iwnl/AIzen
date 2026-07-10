const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Apache/Nginx Access Log Parser
 * Parses lines like:
 * 25.92.32.150 - - [01/Jul/2026:14:58:44 +0000] "DELETE /api/products HTTP/1.1" 200 211 "https://www.bing.com/" "curl/8.5.0"
 */
class ApacheAccessLogParser extends BaseParser {
  constructor() {
    super('apache-access');
    this.lineRegex = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?/;
  }

  parseAccessTimestamp(timestampStr) {
    try {
      const parts = timestampStr.replace(':', ' ').split(' ');
      const dateStr = parts[0].replace(/\//g, ' ') + ' ' + parts[1] + ' ' + (parts[2] || '+0000');
      const date = new Date(dateStr);
      return isNaN(date.getTime()) ? null : date.toISOString();
    } catch {
      return null;
    }
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

    const [, ip, timestampStr, request, statusStr, size, referrer, userAgent] = match;
    const status = parseInt(statusStr, 10);

    let level = 'info';
    if (status >= 500) level = 'error';
    else if (status >= 400) level = 'warn';

    const timestamp = this.parseAccessTimestamp(timestampStr);

    const reqParts = request.split(' ');
    const method = reqParts[0] || 'UNKNOWN';
    const url = reqParts[1] || '';

    const message = `${method} ${url} - Status ${status}`;
    const fingerprint = generateFingerprint(level, `${method} ${url} ${status}`);

    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp,
      level,
      message,
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

module.exports = ApacheAccessLogParser;
