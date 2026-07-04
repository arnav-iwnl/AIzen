/**
 * Base Parser — Abstract base class for log parsers.
 * New log formats (Nginx, syslog, etc.) extend this class.
 */
class BaseParser {
  constructor(formatName) {
    this.formatName = formatName;
  }

  /**
   * Parse a single log line into a structured object.
   * @param {string} line - Raw log line
   * @param {number} lineNumber - Line number in the original file
   * @returns {Object|null} Parsed log entry or null if unparseable
   */
  parseLine(line, lineNumber) {
    throw new Error(`parseLine() must be implemented by ${this.formatName} parser`);
  }

  /**
   * Parse an entire log file content (string of all lines).
   * @param {string} content - Full file content
   * @returns {Object[]} Array of parsed log entries
   */
  parseFile(content) {
    const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
    const parsed = [];
    const errors = [];

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry = this.parseLine(lines[i], i + 1);
        if (entry) {
          parsed.push(entry);
        }
      } catch (err) {
        errors.push({ lineNumber: i + 1, line: lines[i], error: err.message });
      }
    }

    return { parsed, errors, totalLines: lines.length };
  }

  /**
   * Detect if this parser can handle the given content.
   * @param {string} sampleContent - First few lines of the file
   * @returns {boolean}
   */
  canParse(sampleContent) {
    throw new Error(`canParse() must be implemented by ${this.formatName} parser`);
  }
}

module.exports = BaseParser;
