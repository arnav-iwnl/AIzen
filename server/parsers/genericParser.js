const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Generic Fallback Parser
 * Last-resort parser registered at the END of the parser factory.
 * Never rejects a file: every line becomes a message. Best-effort level
 * detection from bracketed keywords or a leading severity word.
 */
class GenericLogParser extends BaseParser {
  constructor() {
    super('generic');

    this.LEVEL_PATTERNS = [
      { level: 'emerg', regex: /\[?\bemerg(?:ency)?\b\]?/i },
      { level: 'alert', regex: /\[?\balert\b\]?/i },
      { level: 'crit', regex: /\[?\bcritical\b\]?|\[?\bcrit\b\]?/i },
      { level: 'error', regex: /\[?\berror\b\]?|\[?\berr\b\]?/i },
      { level: 'warning', regex: /\[?\bwarn(?:ing)?\b\]?/i },
      { level: 'notice', regex: /\[?\bnotice\b\]?/i },
      { level: 'debug', regex: /\[?\bdebug\b\]?/i },
      { level: 'info', regex: /\[?\binfo(?:rmation)?\b\]?/i },
    ];
  }

  detectLevel(line) {
    for (const { level, regex } of this.LEVEL_PATTERNS) {
      if (regex.test(line)) return level;
    }
    return 'unknown';
  }

  parseLine(line, lineNumber) {
    const trimmed = line.trim();
    if (!trimmed) return null;

    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp: null,
      level: this.detectLevel(trimmed),
      message: trimmed,
      fingerprint: generateFingerprint(this.detectLevel(trimmed), trimmed),
      lineNumber,
      parsedAt: new Date().toISOString(),
    };
  }

  canParse() {
    return true; // Always last; accepts anything the other parsers reject
  }
}

module.exports = GenericLogParser;
