/**
 * Regression check: MITRE ATT&CK mapping in the RCA pipeline.
 *
 * Asserts the invariants the UI depends on:
 *  - every technique id is a real ATT&CK id shape and links to its ATT&CK page
 *  - a known credential-file probe maps to T1552.001 (not a guess)
 *  - each attack recommendation carries a technique; each operational one a SYS-* error
 *  - non-attack failures are NEVER labelled as ATT&CK techniques
 *
 * Run: npm run check:mitre
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const attackMap = require('../mitre/attackMap');
const preprocessor = require('../services/preprocessor');
const classificationService = require('../services/classificationService');
const rootCauseService = require('../services/rootCauseService');
const timelineService = require('../services/timelineService');

const ROOT = path.resolve(__dirname, '../..');
const DATA = [
  path.join(ROOT, 'v2/data/ossec-alerts-09.log.txt'),
  path.join(ROOT, 'data/test.log'),
  path.join(ROOT, 'data/access.log'),
];

const ATTACK_ID = /^T\d{4}(\.\d{3})?$/;

let failures = 0;
function check(cond, label) {
  if (cond) console.log(`  ok  ${label}`);
  else { console.error(`  FAIL ${label}`); failures++; }
}

// ── unit: the map itself ───────────────────────────────────────────────────
console.log('=== attackMap unit ===');
check(attackMap.techniqueFor('CREDENTIAL_PROBE').id === 'T1552.001', 'rule CREDENTIAL_PROBE -> T1552.001');
check(attackMap.techniqueFor('credential_probe').id === 'T1552.001', 'v2 credential_probe -> T1552.001');
check(attackMap.techniqueFor('v2:bruteforce').id === 'T1110', 'v2 bruteforce -> T1110 (alias resolved)');
check(attackMap.techniqueFor('v2:xss').id === 'T1059.007', 'v2 xss -> T1059.007 (alias resolved)');
check(attackMap.techniqueFor('v2:scanner').id === 'T1595', 'v2 scanner -> T1595 (alias resolved)');
check(attackMap.techniqueFor('v2:sql-injection').id === 'T1190', 'v2 sql-injection -> T1190');
check(attackMap.techniqueFor('v2:path-traversal').id === 'T1083', 'v2 path-traversal -> T1083');
check(attackMap.techniqueFor('OTHER') === null, 'catch-all OTHER stays unmapped (no invented technique)');
check(attackMap.systemErrorFor('NGINX_UPSTREAM_FAILURE').id === 'SYS-NGINX-UPSTREAM-DOWN', 'nginx upstream -> SYS-* error');
check(attackMap.mitreUrl('T1110.001') === 'https://attack.mitre.org/techniques/T1110/001/', 'sub-technique URL shape');

for (const [fam, tech] of Object.entries(attackMap.TECHNIQUES)) {
  if (!tech) continue;
  check(ATTACK_ID.test(tech.id), `${fam}: ${tech.id} is a valid ATT&CK id`);
  check(Boolean(tech.name && tech.tactic && tech.rationale), `${fam}: has name, tactic and rationale`);
  const url = attackMap.mitreUrl(tech.id);
  check(url.startsWith('https://attack.mitre.org/techniques/'), `${fam}: links to ATT&CK`);
}

// ── integration: the real pipeline ─────────────────────────────────────────
async function runFile(file) {
  if (!fs.existsSync(file)) return false;
  console.log(`\n=== ${path.basename(file)} ===`);
  preprocessor.process(fs.readFileSync(file, 'utf-8'), path.basename(file));
  await classificationService.classify();
  const rc = await rootCauseService.analyze({});
  const a = rc.analysis;

  check(Array.isArray(a.techniques), 'analysis.techniques is an array');
  check(Array.isArray(a.systemErrors), 'analysis.systemErrors is an array');

  for (const t of a.techniques) {
    check(ATTACK_ID.test(t.id), `technique ${t.id} valid`);
    check(t.occurrences > 0, `technique ${t.id} has occurrences`);
    check(t.families.length > 0, `technique ${t.id} names the families that produced it`);
    // One row per FAMILY, not per log pattern (a 22k-line log emits 1358 signals).
    check(
      t.families.length <= Object.keys(attackMap.TECHNIQUES).length,
      `technique ${t.id} families collapsed per family (${t.families.length})`
    );
    check(
      t.families.every((f) => Array.isArray(f.detectedBy) && f.detectedBy.length > 0 && f.detectedBy.every((d) => ['rules', 'v2'].includes(d))),
      `technique ${t.id} records the detecting engine(s)`
    );
    check(
      t.families.reduce((s, f) => s + f.occurrences, 0) === t.occurrences,
      `technique ${t.id} family occurrences sum to the technique total`
    );
  }
  for (const s of a.systemErrors) {
    check(/^SYS-[A-Z0-9-]+$/.test(s.id), `system error ${s.id} uses the SYS-* namespace`);
    check(Boolean(s.meaning && s.fix), `system error ${s.id} has meaning + fix`);
  }

  // Operational failures must never be sold as ATT&CK techniques.
  const nginxOnly = a.systemErrors.filter((s) => s.id.startsWith('SYS-NGINX'));
  const techIds = new Set(a.techniques.map((t) => t.id));
  check(!nginxOnly.some((s) => techIds.has(s.id)), 'no SYS-* error leaked into the ATT&CK list');

  // Recommendations: attacks carry a technique, operational ones carry a SYS-* error.
  for (const r of a.recommendations) {
    const isAttack = Boolean(r.technique);
    const isOperational = Boolean(r.systemError);
    check(isAttack || isOperational, `rec "${r.action.slice(0, 40)}..." carries technique or systemError`);
    if (r.technique) check(ATTACK_ID.test(r.technique.id), `rec technique ${r.technique.id} valid`);
    if (r.systemError) check(/^SYS-/.test(r.systemError.id), `rec systemError ${r.systemError.id} is SYS-*`);
    check(Array.isArray(r.steps) && r.steps.length > 0, `rec "${r.action.slice(0, 30)}..." still has recovery steps`);
  }

  // The narrative names the techniques when there are any.
  if (a.techniques.length > 0) {
    check(/MITRE ATT&CK/.test(a.rootCause), 'rootCause narrative names the ATT&CK techniques');
    check(a.techniques.every((t) => a.rootCause.includes(t.id)), 'every technique id appears in the narrative');
  }

  // Timeline events must not fabricate ATT&CK (Phase 3 wires techniques there).
  const tl = await timelineService.generateTimeline({ focus: 'errors', maxEvents: 12 });
  check(
    tl.timeline.every((e) => !/T\d{4}\.\d{3}/.test(e.summary) || /MITRE/.test(e.summary)),
    'timeline summaries do not cite techniques yet (Phase 3 owns that)'
  );
  return true;
}

(async () => {
  let ran = 0;
  for (const f of DATA) if (await runFile(f)) ran++;
  check(ran > 0, `ran against ${ran} real log file(s)`);
  console.log(failures === 0 ? '\ncheck:mitre OK' : `\ncheck:mitre FAILED (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('check:mitre ERROR:', e); process.exit(1); });
