const ApacheLogParser = require('./apacheLogParser');
const ApacheAccessLogParser = require('./apacheAccessLogParser');
const logger = require('../utils/logger');

/**
 * Parser Factory — Strategy pattern for log format detection.
 * Automatically detects the log format and returns the appropriate parser.
 * New formats can be added by registering new parser classes.
 */
class ParserFactory {
  constructor() {
    // Register all available parsers
    this.parsers = [
      new ApacheLogParser(),
      new ApacheAccessLogParser(),
      // Future: new NginxLogParser(),
      // Future: new SyslogParser(),
    ];
  }

  /**
   * Detect the format from sample content and return the matching parser.
   * @param {string} content - Full or sample file content
   * @returns {BaseParser} The matching parser
   * @throws {Error} If no parser can handle the content
   */
  getParser(content) {
    // Take a sample (first 10 lines) for format detection
    const sampleLines = content.split(/\r?\n/).filter((l) => l.trim()).slice(0, 10);
    const sample = sampleLines.join('\n');

    for (const parser of this.parsers) {
      if (parser.canParse(sample)) {
        logger.info(`Detected log format: ${parser.formatName}`);
        return parser;
      }
    }

    throw new Error(
      'Unable to detect log format. Supported formats: ' +
      this.parsers.map((p) => p.formatName).join(', ')
    );
  }

  /**
   * Detect the format from a file by reading its first few lines.
   * @param {string} filePath - Path to the log file
   * @returns {Promise<BaseParser>} The matching parser
   */
  async getParserFromFile(filePath) {
    const fs = require('fs');
    const readline = require('readline');
    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let sample = '';
    let lineCount = 0;

    for await (const line of rl) {
      if (line.trim()) {
        sample += line + '\n';
        lineCount++;
      }
      if (lineCount >= 10) break;
    }

    rl.close();
    fileStream.destroy();

    return this.getParser(sample);
  }

  /**
   * Get a parser by explicit format name.
   * @param {string} formatName - e.g., "apache"
   * @returns {BaseParser}
   */
  getParserByName(formatName) {
    const parser = this.parsers.find((p) => p.formatName === formatName);
    if (!parser) {
      throw new Error(`Unknown log format: ${formatName}`);
    }
    return parser;
  }
}

// Singleton
module.exports = new ParserFactory();
