/**
 * smoke.js — end-to-end sanity check for the LOCAL analysis pipeline.
 *
 * Directly exercises the services (no HTTP server) against every file in
 * data/ and asserts the response schemas. Exits non-zero on failure.
 *
 * Run: npm run smoke   (from server/)
 */
const fs = require('fs');
const path = require('path');
const preprocessor = require('../services/preprocessor');
const classificationService = require('../services/classificationService');
const incidentService = require('../services/incidentService');
const timelineService = require('../services/timelineService');
const rootCauseService = require('../services/rootCauseService');

const DATA_DIR = path.resolve(__dirname, '../../data');
const FILES = ['access.log', 'Apache_2k.log', 'synthetic_error.log', 'test.log', 'acunetix.log'];

let failures = 0;

function assert(cond, label) {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    console.error(`  ✗ ${label}`);
    failures++;
  }
}

async function run() {
  for (const file of FILES) {
    const filePath = path.join(DATA_DIR, file);
    if (!fs.existsSync(filePath)) continue;

    console.log(`\n=== ${file} ===`);
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = preprocessor.process(content, file);
    assert(parsed.parsedLines > 0, `parsed ${parsed.parsedLines} lines (${parsed.format})`);
    assert(parsed.uniquePatterns > 0, `${parsed.uniquePatterns} unique patterns`);

    const cls = await classificationService.classify();
    assert(cls.engine === 'local', `classification engine=local (${cls.processingTimeMs}ms)`);
    assert(cls.classifications.length === parsed.uniquePatterns, 'all patterns classified');
    assert(cls.summary && cls.summary.dominantCategory, 'summary present');
    const allFields = cls.classifications.every(
      (c) => c.classification && c.classification.category && c.classification.severity && c.classification.confidence >= 0
    );
    assert(allFields, 'classification schema valid');

    const det = await incidentService.detect();
    assert(Array.isArray(det.incidents), `incident detection ran (${det.processingTimeMs}ms)`);
    if (det.incidents.length > 0) {
      assert(det.incidents.every((i) => i.title && i.severity && i.signals.length > 0), 'incident schema valid');
    }

    const tl = await timelineService.generateTimeline({ focus: 'errors', maxEvents: 8 });
    assert(tl.timeline && Array.isArray(tl.timeline), `timeline ran (${tl.processingTimeMs}ms)`);
    assert(tl.overallSummary, 'timeline summary present');
    if (tl.timeline.length > 0) {
      assert(tl.timeline.every((e) => e.eventTitle && e.severity && e.timestamp), 'timeline schema valid');
    }

    const rc = await rootCauseService.analyze({});
    assert(rc.analysis && rc.analysis.rootCause, `RCA ran (${rc.processingTimeMs}ms)`);
    assert(rc.analysis.confidence > 0 && Array.isArray(rc.analysis.recommendations), 'RCA schema valid');
  }

  console.log(`\n${failures === 0 ? 'SMOKE PASS' : `SMOKE FAIL (${failures})`}`);
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((err) => {
  console.error('SMOKE ERROR:', err);
  process.exit(1);
});
