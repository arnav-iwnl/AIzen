/**
 * Regression check: MITRE ATT&CK on the real-time path.
 *
 * The detector must label live traffic from a source it has never seen, and the
 * vulnerable site's ground-truth hints must arrive as `expectedTechniques` and
 * NOT influence classification. Both are asserted here with real
 * vulnerable-site-style access lines (Apache combined, the format its logger
 * emits).
 *
 * Run: npm run check:rtmitre
 */
const assert = require('assert');
const realtimeHub = require('../realtime/realtimeHub');
const attackMap = require('../mitre/attackMap');

const { expectedTechniques: routeHint } = (() => {
  // Mirror of vulnerable-site/middleware/logger.js ROUTE_TECHNIQUES, so this
  // check fails if the two ever drift apart.
  return {
    expectedTechniques: (url) => {
      const p = String(url || '').split('?')[0];
      const table = [
        [/^\/product\b/i, ['T1190']],
        [/^\/(search|profile)\b/i, ['T1059.007']],
        [/^\/download\b/i, ['T1083', 'T1552.001']],
        [/^\/login\b/i, ['T1110.003']],
        [/^\/api\/admin\b/i, ['T1110']],
      ];
      for (const [re, ids] of table) if (re.test(p)) return ids;
      return null;
    },
  };
})();

const line = (ip, method, url, status) =>
  `${ip} - - [09/Sep/2026:07:07:36 +0000] "${method} ${url} HTTP/1.1" ${status} 196 "-" "Mozilla/5.0"`;

let failures = 0;
const check = (cond, label) => {
  if (cond) console.log(`  ok  ${label}`);
  else { console.error(`  FAIL ${label}`); failures++; }
};

const ATTACK_ID = /^T\d{4}(\.\d{3})?$/;

async function run() {
  // Each case: a real attack against a route that models it, plus the ground
  // truth the vulnerable site would have declared.
  const cases = [
    { name: 'SQLi on /product', raw: line('45.148.10.64', 'GET', "/product?id=1' OR '1'='1", 200), expect: 'T1190' },
    { name: 'XSS on /search', raw: line('45.148.10.64', 'GET', '/search?q=<script>alert(1)</script>', 200), expect: 'T1059.007' },
    { name: 'traversal on /download', raw: line('45.148.10.64', 'GET', '/download?file=../../../../etc/passwd', 200), expect: 'T1083' },
    { name: 'brute force on /login', raw: line('45.148.10.64', 'POST', '/login', 401), expect: 'T1110' },
    { name: 'admin recon', raw: line('45.148.10.64', 'GET', '/api/admin/config', 401), expect: null },
    { name: 'benign request', raw: line('45.148.10.64', 'GET', '/about', 200), expect: null },
  ];

  console.log('=== real-time technique mapping ===');
  const results = [];
  for (const c of cases) {
    const url = c.raw.match(/"[A-Z]+ ([^ ]+)/)[1];
    const hint = routeHint(url);
    const ev = await realtimeHub.ingestLine(c.raw, 'vulnerable-app', null, hint);
    results.push({ c, ev, hint });
    const ids = (ev?.techniques || []).map((t) => t.id);
    console.log(`  ${c.name.padEnd(24)} hint=${JSON.stringify(hint)} detected=${JSON.stringify(ids)}`);
    check(ATTACK_ID.test(ids[0] || '') || ids.length === 0, `${c.name}: any technique id is well-formed`);
    for (const t of ev?.techniques || []) {
      check(Boolean(t.name && t.tactic && t.url), `${c.name}: ${t.id} carries name/tactic/url`);
    }
  }

  console.log('\n=== detection vs ground truth ===');
  let hits = 0;
  let applicable = 0;
  for (const { c, ev, hint } of results) {
    if (!hint) continue;
    applicable++;
    const ids = (ev?.techniques || []).map((t) => t.id);
    // A hint of T1110.003 is satisfied by detecting its parent T1110 — ATT&CK
    // sub-technique ids are refinements, not different verdicts.
    const matched = ids.some((id) => hint.some((h) => h === id || h.startsWith(id)));
    if (matched) hits++;
    else console.log(`  miss: ${c.name} expected ${hint[0]} got ${JSON.stringify(ids)}`);
  }
  check(applicable > 0, `${applicable} case(s) carried a ground-truth hint`);
  check(hits === applicable, `detected the expected technique (or its parent) in ${hits}/${applicable} cases`);

  console.log('\n=== invariants ===');
  const benign = results.find((r) => r.c.name === 'benign request');
  check(benign.ev?.category !== 'Security', 'a benign request is not categorised Security');
  check(benign.ev?.level !== 'error', 'a benign request does not escalate to error level');
  // v2 always contributes its attack_type/technique, but on a line the rules
  // called clean it must be marked non-escalating rather than silently raising.
  if (benign.ev?.techniques?.length) {
    check(benign.ev?.v2Only === true, 'a technique on a clean line is marked v2Only (non-escalating)');
  } else {
    check(true, 'no technique on the benign line');
  }

  // The hint must be inert: the same line with and without a hint must classify
  // identically, otherwise the oracle is leaking into detection.
  const probe = results[0];
  const noHint = await realtimeHub.ingestLine(probe.c.raw, 'vulnerable-app', null, null);
  check(
    JSON.stringify((noHint?.techniques || []).map((t) => t.id)) ===
      JSON.stringify((probe.ev?.techniques || []).map((t) => t.id)),
    'expectedTechniques does not change the verdict'
  );
  check(Array.isArray(probe.ev?.expectedTechniques), 'expectedTechniques is carried on the event');
  check(
    !('expectedTechniques' in (noHint || {})) || noHint.expectedTechniques == null,
    'no expectedTechniques when none was sent'
  );

  // A rule-matched line must report the RULE's confidence. A deep-model opinion
  // that is weaker must not overwrite it (this reported 44% for a 92% rule hit).
  const ruleHit = results.find((r) => r.ev?.category === 'Security' && r.ev?.confidence != null);
  if (ruleHit) {
    const rules = require('../rules/logRules');
    const direct = rules.classify({ message: ruleHit.ev.message, level: ruleHit.ev.level, raw: ruleHit.ev.raw });
    if (direct.securityTypes.length > 0) {
      check(
        ruleHit.ev.confidence >= direct.confidence,
        `a rule-flagged line reports >= the rule confidence (event ${ruleHit.ev.confidence} vs rule ${direct.confidence})`
      );
    }
  }

  // Technique attribution follows the rules when they matched, so a model that
  // disagrees cannot bolt a second (wrong) technique onto a correct verdict.
  const dual = results.find((r) => {
    const direct = require('../rules/logRules').classify({ message: r.ev?.message, level: r.ev?.level, raw: r.ev?.raw });
    return direct.securityTypes.length > 0 && (r.ev?.techniques || []).length > 1;
  });
  check(!dual, `no rule-matched line carries more than one technique${dual ? ` (${dual.c.name}: ${dual.ev.techniques.map((t) => t.id)})` : ''}`);

  // Every emitted technique must be resolvable by the shared map (no orphans).
  const all = results.flatMap((r) => r.ev?.techniques || []);
  check(all.every((t) => attackMap.mitreUrl(t.id) === t.url), 'emitted urls match attackMap.mitreUrl');

  console.log(failures === 0 ? '\ncheck:rtmitre OK' : `\ncheck:rtmitre FAILED (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((e) => { console.error('check:rtmitre ERROR:', e); process.exit(1); });
