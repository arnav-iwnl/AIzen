const parserFactory = require('../parsers/parserFactory');
const logStore = require('../store/logStore');
const logger = require('../utils/logger');

/**
 * Preprocessor Service
 * Handles the complete pipeline: raw file content → parsed → indexed in memory.
 */
class Preprocessor {
  /**
   * Process a raw log file and load it into the LogStore.
   * @param {string} content - Raw file content
   * @param {string} fileName - Source file name
   * @returns {Object} Processing result with stats
   */
  process(content, fileName = 'unknown') {
    const startTime = Date.now();

    // Step 1: Detect format and get appropriate parser
    const parser = parserFactory.getParser(content);

    // Step 2: Parse all lines
    const { parsed, errors, totalLines } = parser.parseFile(content);

    logger.info(`Parsed ${parsed.length}/${totalLines} lines (${errors.length} errors)`, {
      format: parser.formatName,
      fileName,
    });

    // Step 3: Ingest into LogStore (builds all indexes)
    logStore.ingest(parsed, fileName);

    const processingTime = Date.now() - startTime;

    return {
      fileName,
      format: parser.formatName,
      totalLines,
      parsedLines: parsed.length,
      parseErrors: errors.length,
      uniquePatterns: logStore.stats.uniquePatterns,
      processingTimeMs: processingTime,
      stats: logStore.getStats(),
    };
  }

  /**
   * Stream and process a log file from disk, minimizing memory usage.
   * @param {string} filePath - Path to uploaded file
   * @param {string} fileName - Source file name
   * @returns {Promise<Object>} Processing result with stats
   */
  async processFileStream(filePath, fileName = 'unknown') {
    const fs = require('fs');
    const readline = require('readline');
    
    const startTime = Date.now();

    // Step 1: Detect format using the new file-based detector
    const parser = await parserFactory.getParserFromFile(filePath);

    // Step 2: Clear store and prepare for stream processing
    logStore.clearStore();
    
    let totalLines = 0;
    let parsedCount = 0;
    let errorCount = 0;
    let batch = [];
    const BATCH_SIZE = 10000;

    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    for await (const line of rl) {
      if (!line.trim()) continue;
      
      totalLines++;
      try {
        const entry = parser.parseLine(line, totalLines);
        if (entry) {
          batch.push(entry);
          parsedCount++;
        }
      } catch (err) {
        errorCount++;
      }

      if (batch.length >= BATCH_SIZE) {
        logStore.ingestBatch(batch);
        batch = [];
      }
    }

    if (batch.length > 0) {
      logStore.ingestBatch(batch);
    }

    // Step 3: Finalize ingestion (sort, build indexes)
    logStore.finalizeIngest(fileName);

    // Step 4: Cleanup temp file
    try {
      fs.unlinkSync(filePath);
    } catch (err) {
      logger.warn(`Failed to delete temp file: ${filePath}`);
    }

    const processingTime = Date.now() - startTime;

    logger.info(`Stream Parsed ${parsedCount}/${totalLines} lines (${errorCount} errors)`, {
      format: parser.formatName,
      fileName,
    });

    return {
      fileName,
      format: parser.formatName,
      totalLines,
      parsedLines: parsedCount,
      parseErrors: errorCount,
      uniquePatterns: logStore.stats.uniquePatterns,
      processingTimeMs: processingTime,
      stats: logStore.getStats(),
    };
  }

  /**
   * Process an array of raw log lines (for API-submitted logs).
   * @param {string[]} lines - Array of raw log line strings
   * @returns {Object[]} Parsed log entries (not stored — used for classification)
   */
  parseLines(lines) {
    const content = Array.isArray(lines) ? lines.join('\n') : lines;
    const parser = parserFactory.getParser(content);
    const { parsed } = parser.parseFile(content);
    return parsed;
  }
}

module.exports = new Preprocessor();
