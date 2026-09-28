/**
 * Regression check: the v2Detections fingerprint join.
 *
 * Contract (v2Detections.js): the registry holds ONLY fingerprints the v2 deep
 * classifier flagged as attacks. Every consumer branches on `v2 ? v2Verdict :
 * ruleVerdict` (localRootCauseService.js:144, localTimelineService.js:54,130),
 * so a rule-only hit recorded in the registry fabricates a deep-model verdict —
 * it printed "Deep classifier detected rule attack (0.0% confidence)" in the
 * timeline and forced system errors (nginx) to category "Security".
 *
 * Run: npm run check:join
 */
const assert = require('assert');
const path = require('path');

const v2Bridge = require('../ml/v2Bridge');
const v2Detections = require('../ml/v2Detections');
const detectorService = require('../services/detectorService');
const rules = require('../rules/logRules');
const localTimelineService = require('../services/localTimelineService');
const parserFactory = require('../parsers/parserFactory');

// ponytail: stub the ONNX bridge so the rule-only branch is deterministic and
// the check runs in milliseconds. Real v2 verdicts are covered by case C.
const stubV2 = (verdictFor) => {
  v2Bridge.classifyBatch = async (texts) => texts.map(verdictFor);
};

const LINES = {
  // rule-only ATTACK: 403 on an admin path -> ADMIN_BRUTE_FORCE / CREDENTIAL_PROBE
  security: '10.1.1.5 - - [10/Oct/2026:13:55:36 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "curl/8.4.0"',
  // rule-only SYSTEM error: nginx upstream failure -> NGINX_UPSTREAM_FAILURE (Warning, not an attack)
  system: '2026/10/10 13:55:36 [error] 1234#0: *5678 connect() failed (111: Connection refused) while connecting to upstream, client: 10.1.1.5, server: localhost, request: "GET /api HTTP/1.1", host: "localhost"',
  // benign -> no rule match, so only v2 can flag it
  benign: 'Oct 10 13:55:36 app started worker pool size 4',
};

function parse(raw) {
  const parser = parserFactory.getParser(raw);
  const entry = parser.parseLine(raw, 0);
  entry.format = parser.formatName;
  return { ...entry, raw, occurrenceCount: 1 };
}

async function run() {
  const patterns = Object.values(LINES).map(parse);

  // ── A + B: v2 is unsure -> registry must stay empty ──────────────────────
  stubV2(() => ({ is_attack: false, attack_type: 'none', attack_confidence: 0 }));
  await detectorService.classify(patterns, Date.now());

  const ruleOnly = patterns.filter((p) => rules.classify(p).securityTypes.length > 0);
  assert.ok(ruleOnly.length >= 2, `expected >=2 rule-matched patterns, got ${ruleOnly.length}`);

  for (const p of ruleOnly) {
    const v2 = v2Detections.get(p.fingerprint);
    assert.strictEqual(
      v2, null,
      `registry must not hold a rule-only hit (fingerprint ${p.fingerprint}, types ${rules.classify(p).securityTypes.join('/')}) — got ${JSON.stringify(v2)}`
    );
  }
  assert.strictEqual(v2Detections.size(), 0, `registry should be empty when v2 flags nothing, holds ${v2Detections.size()}`);

  // The user-visible text must not claim a deep-model verdict.
  for (const p of patterns) {
    const summary = localTimelineService._summary(p, rules.classify(p), v2Detections.get(p.fingerprint));
    assert.ok(
      !/Deep classifier detected rule attack/.test(summary),
      `timeline summary fabricates a v2 verdict: "${summary}"`
    );
  }

  // A system error must stay a system error, not be escalated to Security by a
  // non-existent v2 verdict.
  const sysLine = patterns.find((p) => rules.classify(p).securityTypes.some((t) => t.startsWith('NGINX_')));
  assert.ok(sysLine, 'expected an nginx system-error pattern');
  assert.strictEqual(rules.classify(sysLine).category, 'Warning', 'fixture should be an nginx warning');
  assert.strictEqual(
    v2Detections.get(sysLine.fingerprint) ? 'Security' : rules.classify(sysLine).category,
    'Warning',
    'nginx upstream failure was escalated to Security by a phantom v2 verdict'
  );

  // ── C: genuine v2 attack must still be recorded and surfaced ─────────────
  stubV2(() => ({ is_attack: true, attack_type: 'sql-injection', attack_confidence: 0.97 }));
  await detectorService.classify([patterns[2]], Date.now()); // benign line

  const hit = v2Detections.get(patterns[2].fingerprint);
  assert.ok(hit, 'genuine v2 verdict was not recorded');
  assert.strictEqual(hit.attack_type, 'sql-injection');
  assert.strictEqual(hit.confidence, 0.97);
  assert.match(
    localTimelineService._summary(patterns[2], rules.classify(patterns[2]), hit),
    /Deep classifier detected sql-injection attack \(97\.0% confidence\)/,
    'genuine v2 verdict not surfaced in the timeline summary'
  );

  // ── D: a real rule pattern flagged by v2 keeps BOTH verdicts ──────────────
  stubV2(() => ({ is_attack: true, attack_type: 'bruteforce', attack_confidence: 0.91 }));
  await detectorService.classify([patterns[0]], Date.now()); // rule-matched security line

  const both = v2Detections.get(patterns[0].fingerprint);
  assert.ok(both, 'rule+v2 pattern lost its v2 verdict');
  assert.strictEqual(both.attack_type, 'bruteforce');
  const cls = rules.classify(patterns[0]);
  assert.ok(cls.securityTypes.length > 0, 'fixture should still be rule-matched');
  assert.ok(
    /Deep classifier detected bruteforce/.test(localTimelineService._summary(patterns[0], cls, both)),
    'rule+v2 pattern should report the deep-model verdict'
  );

  console.log('check:join OK — registry holds only real v2 verdicts; rule-only and system-error paths stay clean');
}

run().catch((err) => {
  console.error('check:join FAILED:', err.message);
  process.exit(1);
});
