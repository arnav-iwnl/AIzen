const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Syslog Parser — RFC3164 and RFC5424
 *
 * RFC3164:  <134>Jan 15 10:30:00 myhost sshd[1234]: Failed password for root
 * RFC5424:  <165>1 2003-10-11T22:14:15.003Z myhost sshd 1234 ID47 - message
 * Variant:  Jan 15 10:30:00 myhost sshd[1234]: message   (no PRI)
 * Variant:  <13>2024-01-15T10:30:00.000Z myhost app: message
 *
 * A timestamp (or PRI) is REQUIRED so unknown text formats fall through
 * to the generic parser instead of being swallowed here.
 */
class SyslogParser extends BaseParser {
  constructor() {
    super('syslog');

    // Severity index (0..7) → level name
    this.SEVERITY_NAMES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

    this.RFC3164_TS = '[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}';
    this.ISO_TS = '\\d{4}-\\d{2}-\\d{2}T[^\\s]+';

    // Group 1: PRI, Group 2: RFC5424 version, Group 3: timestamp, Group 4: hostname, Group 5: message
    this.lineRegex = new RegExp(
      '^(?:<(\\d{1,3})>)?(?:\\d\\s+)?(' + this.ISO_TS + '|' + this.RFC3164_TS + ')\\s+(\\S+)\\s+(.+)$'
    );
  }

  parseTimestamp(timestampStr) {
    if (!timestampStr) return null;
    let date;
    if (timestampStr.includes('T')) {
      date = new Date(timestampStr);
    } else {
      // RFC3164: "Jan 15 10:30:00" → assume current year
      const currentYear = new Date().getFullYear();
      date = new Date(`${timestampStr} ${currentYear}`);
      // ponytail: crosses year boundaries wrong by one year; fine for heuristic parsing.
    }
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

    const [, priStr, timestampStr, hostname, rest] = match;

    let level = 'info';
    if (priStr) {
      const severity = parseInt(priStr, 10) % 8;
      level = this.SEVERITY_NAMES[severity];
    } else {
      const bracketLevel = rest.match(/\[(\w+)\]/);
      if (bracketLevel && ['error', 'warn', 'warning', 'crit', 'info', 'notice', 'debug'].includes(bracketLevel[1].toLowerCase())) {
        level = bracketLevel[1].toLowerCase();
      }
    }

    const timestamp = this.parseTimestamp(timestampStr);
    const message = rest.trim();
    const fingerprint = generateFingerprint(level, message);

    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp,
      level,
      message,
      fingerprint,
      lineNumber,
      parsedAt: new Date().toISOString(),
      hostname: hostname || null,
    };
  }

  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 5);
    if (lines.length === 0) return false;

    const matchCount = lines.filter((line) => this.lineRegex.test(line)).length;
    return matchCount / lines.length >= 0.5;
  }
}

module.exports = SyslogParser;
