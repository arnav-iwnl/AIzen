/**
 * seedLabels.js — build the rule-labeled training corpus.
 *
 * Parses every file in data/, deduplicates to fingerprint patterns, and
 * auto-labels each pattern via the rule classifier (logRules.js).
 * Writes data/labeled/patterns.jsonl — one JSON object per pattern.
 *
 * Run: node server/scripts/seedLabels.js
 */
const fs = require('fs');
const path = require('path');
const parserFactory = require('../parsers/parserFactory');
const { classify } = require('../rules/logRules');
const logger = require('../utils/logger');

const DATA_DIR = path.resolve(__dirname, '../../data');
const LABELED_DIR = path.join(DATA_DIR, 'labeled');
const OUTPUT = path.join(LABELED_DIR, 'patterns.jsonl');

const FILES = ['access.log', 'Apache_2k.log', 'synthetic_error.log', 'test.log', 'acunetix.log'];

function loadPatterns() {
  const byFp = new Map();

  for (const file of FILES) {
    const filePath = path.join(DATA_DIR, file);
    if (!fs.existsSync(filePath)) {
      logger.warn(`Skipping missing data file: ${file}`);
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    let parser;
    try {
      parser = parserFactory.getParser(content);
    } catch (err) {
      logger.warn(`Could not detect format for ${file}: ${err.message}`);
      continue;
    }

    const { parsed, parseErrors } = parser.parseFile(content);
    logger.info(`Parsed ${file}: ${parsed.length} lines (${parseErrors} errors), format=${parser.formatName}`);

    for (const log of parsed) {
      if (!byFp.has(log.fingerprint)) {
        byFp.set(log.fingerprint, {
          ...log,
          occurrenceCount: 1,
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
        });
      } else {
        const p = byFp.get(log.fingerprint);
        p.occurrenceCount++;
        if (log.timestamp) {
          if (!p.firstSeen || log.timestamp < p.firstSeen) p.firstSeen = log.timestamp;
          if (!p.lastSeen || log.timestamp > p.lastSeen) p.lastSeen = log.timestamp;
        }
      }
    }
  }

  return Array.from(byFp.values());
}

function main() {
  if (!fs.existsSync(LABELED_DIR)) fs.mkdirSync(LABELED_DIR, { recursive: true });

  const patterns = loadPatterns();
  const lines = [];

  for (const p of patterns) {
    const label = classify({ message: p.message, level: p.level, raw: p.raw });
    lines.push(
      JSON.stringify({
        id: p.fingerprint,
        raw: p.raw,
        message: p.message,
        level: p.level,
        occurrenceCount: p.occurrenceCount,
        firstSeen: p.firstSeen || null,
        lastSeen: p.lastSeen || null,
        category: label.category,
        severity: label.severity,
        confidence: label.confidence,
        matchedRule: label.matchedRule,
        securityTypes: label.securityTypes,
        status: label.status,
        reviewed: false,
      })
    );
  }

  fs.writeFileSync(OUTPUT, lines.join('\n') + '\n');
  logger.info(`Wrote ${patterns.length} labeled patterns to ${OUTPUT}`);
}

main();
