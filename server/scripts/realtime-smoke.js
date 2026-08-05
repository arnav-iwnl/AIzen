/**
 * realtime-smoke.js — sanity check for the real-time SIEM + demo generator.
 *
 * Exercises demoService + realtimeHub directly (no HTTP server) and asserts
 * generated lines parse, classify, and flow into the hub correctly.
 *
 * Run: npm run smoke:realtime   (from server/)
 */
const demoService = require('../demo/demoService');
const realtimeHub = require('../realtime/realtimeHub');

let failures = 0;

function assert(cond, label) {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    console.error(`  ✗ ${label}`);
    failures++;
  }
}

realtimeHub.clear();

console.log('\n=== demo actions ===');
const actions = demoService.getActions();
assert(actions.length >= 11, `${actions.length} actions available`);

console.log('\n=== trigger sqli x5 ===');
let res = demoService.trigger('sqli', 5);
assert(res.generated === 5, `generated ${res.generated}/5`);
let ev = realtimeHub.events.slice(-5);
assert(ev.every((e) => e.securityTypes.includes('SQL_INJECTION')), 'all SQLi lines flagged');
assert(ev.every((e) => e.category === 'Security'), 'all classified as Security');

console.log('\n=== trigger get-flood x3 ===');
demoService.trigger('get-flood', 3);
ev = realtimeHub.events.slice(-3);
assert(ev.every((e) => e.category === 'Request Processing' && e.securityTypes.length === 0), 'GET flood classified as normal traffic');

console.log('\n=== trigger backend-error x3 ===');
demoService.trigger('backend-error', 3);
ev = realtimeHub.events.slice(-3);
assert(ev.every((e) => e.level === 'error'), 'backend errors level=error');
assert(ev.every((e) => e.category === 'Backend Communication' || e.category === 'Security'), 'backend errors categorized');

console.log('\n=== trigger mixed x10 + directory-forbidden x3 ===');
demoService.trigger('mixed', 10);
demoService.trigger('directory-forbidden', 3);
assert(realtimeHub.counters.total >= 24, `counters.total=${realtimeHub.counters.total}`);
assert(realtimeHub.counters.security >= 5, `counters.security=${realtimeHub.counters.security}`);

console.log('\n=== schema ===');
const snap = realtimeHub.getSnapshot();
assert(Array.isArray(snap.events) && snap.events.length > 0, 'snapshot has events');
assert(Array.isArray(snap.alerts), 'snapshot has alerts');
assert(snap.counters && typeof snap.counters.total === 'number', 'snapshot has counters');
const wellFormed = snap.events.every(
  (e) => e.id && e.ts && e.raw && e.level && e.category && e.severity && Array.isArray(e.securityTypes)
);
assert(wellFormed, 'every event is well-formed');
const allHaveFormat = snap.events.every((e) => e.format && typeof e.raw === 'string');
assert(allHaveFormat, 'every event has a detected format');

console.log(`\n${failures === 0 ? 'REALTIME SMOKE PASS' : `REALTIME SMOKE FAIL (${failures})`}`);
process.exit(failures === 0 ? 0 : 1);
