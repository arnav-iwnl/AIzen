/**
 * Cross-domain detection gate for the v2 deep classifier.
 *
 * WHY THIS EXISTS
 * The training pipeline used a random row split of one pooled corpus, so its
 * val F1 was structurally blind to generalization failure. A retrain on a
 * rebalanced corpus scored val F1 0.983 while its FALSE POSITIVE RATE on
 * held-out SIEM data got worse (10.8% -> 14.8%) and attack recall fell
 * (90.4% -> 73.0%). This script is the gate that would have caught it.
 *
 * It measures what production actually does — v2Bridge.classifyBatch, i.e. the
 * same code path the realtime hub and the upload pipeline use — against log
 * formats the model was NOT trained on (v2/data/ingest/*.jsonl: OSSEC +
 * Wazuh alert corpora).
 *
 * Usage:
 *   npm run check:model            # fail on regression vs the stored baseline
 *   npm run check:model -- --update   # (re)write the baseline
 *   npm run check:model -- --json     # machine-readable only
 *
 * NOTE: batches are chunked. A single 2636-row inference makes onnxruntime try
 * to allocate ~10GB inside the LSTM node and hard-fails; 256 is safe.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const BASELINE_PATH = path.join(ROOT, 'v2/eval/baseline.json');
const INGEST_DIR = path.join(ROOT, 'v2/data/ingest');
const RUNTIME_META = path.join(ROOT, 'v2/runtime/meta.json');
const CHUNK = 256;

// Absolute sanity bar — catches catastrophe even with no baseline present.
const MAX_BENIGN_FP_RATE = 0.25;

const argv = process.argv.slice(2);
const UPDATE = argv.includes('--update');
const AS_JSON = argv.includes('--json');

const loadJsonl = (p) =>
  fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));

/** First occurrence of each distinct message keeps the corpus order stable. */
function uniqueRows(rows, wantAttack) {
  const seen = new Set();
  const out = [];
  for (const r of rows) {
    if (!!r.is_attack !== wantAttack) continue;
    if (!r.message || seen.has(r.message)) continue;
    seen.add(r.message);
    out.push(r);
  }
  return out;
}

async function classify(v2Bridge, messages) {
  const out = [];
  for (let i = 0; i < messages.length; i += CHUNK) {
    out.push(...(await v2Bridge.classifyBatch(messages.slice(i, i + CHUNK))));
  }
  return out;
}

function rate(hit, total) {
  return total ? hit / total : 0;
}

async function main() {
  const v2Bridge = require(path.join(ROOT, 'server/ml/v2Bridge'));

  if (!fs.existsSync(INGEST_DIR)) {
    console.error(`check:model: no ingest corpora at ${INGEST_DIR} — run "python -m ingest.normalize" first.`);
    process.exit(1);
  }

  const sources = fs.readdirSync(INGEST_DIR).filter((f) => f.endsWith('.jsonl')).sort();
  const metrics = { chunk: CHUNK, sets: {}, perClass: {}, thresholdsComplete: true, problems: [] };

  for (const file of sources) {
    const rows = loadJsonl(path.join(INGEST_DIR, file));
    const benign = uniqueRows(rows, false);
    const attack = uniqueRows(rows, true);
    if (benign.length === 0 && attack.length === 0) continue;

    const set = { benign: { n: benign.length, flagged: 0, byType: {} }, attack: { n: attack.length, flagged: 0, byType: {}, byTrueType: {} } };

    if (benign.length) {
      const res = await classify(v2Bridge, benign.map((r) => r.message));
      res.forEach((r, i) => {
        if (!r || !r.is_attack) return;
        set.benign.flagged++;
        const t = r.attack_type || '?';
        set.benign.byType[t] = (set.benign.byType[t] || 0) + 1;
        // The dominant documented failure: a benign Cisco switch syslog
        // ("%% Session 0 of type 2 ended") scored as bruteforce.
        if (/Network switch session ended|Spanning Tree Topology Change|Logging Count .* exceeds threshold/i.test(benign[i].message)) {
          set.benign.wrapperFp = (set.benign.wrapperFp || 0) + 1;
        }
      });
    }

    if (attack.length) {
      const res = await classify(v2Bridge, attack.map((r) => r.message));
      res.forEach((r, i) => {
        const trueType = attack[i].attack_type || 'other';
        set.attack.byTrueType[trueType] = set.attack.byTrueType[trueType] || { n: 0, hit: 0 };
        set.attack.byTrueType[trueType].n++;
        if (r && r.is_attack) {
          set.attack.flagged++;
          const t = r.attack_type || '?';
          set.attack.byType[t] = (set.attack.byType[t] || 0) + 1;
          if (t === trueType) set.attack.byTrueType[trueType].hit++;
        }
      });
    }

    set.benign.fpRate = rate(set.benign.flagged, set.benign.n);
    set.attack.recall = rate(set.attack.flagged, set.attack.n);
    metrics.sets[file.replace(/\.jsonl$/, '')] = set;
  }

  // Pooled per-class recall across every source.
  for (const set of Object.values(metrics.sets)) {
    for (const [cls, v] of Object.entries(set.attack.byTrueType)) {
      const agg = metrics.perClass[cls] || (metrics.perClass[cls] = { n: 0, hit: 0 });
      agg.n += v.n;
      agg.hit += v.hit;
    }
  }
  for (const [cls, v] of Object.entries(metrics.perClass)) {
    v.recall = rate(v.hit, v.n);
  }

  // Every class the model can emit must carry an explicit threshold. A class
  // without one silently inherits the strictest global default in
  // onnx_classifier.js:120 and becomes effectively undetectable.
  let labelSpace = null;
  try {
    const meta = JSON.parse(fs.readFileSync(RUNTIME_META, 'utf8'));
    const per = meta.attack_thresholds || {};
    labelSpace = new Set(Object.keys(meta.attack_index));
    const missing = [...labelSpace].filter((c) => c !== 'none' && per[c] === undefined);
    metrics.thresholdsComplete = missing.length === 0;
    if (!metrics.thresholdsComplete) metrics.problems.push(`classes without an explicit attack_thresholds entry: ${missing.join(', ')}`);
  } catch (e) {
    metrics.problems.push(`cannot read ${RUNTIME_META}: ${e.message}`);
  }

  // A label the deployed model cannot emit can never be recalled, so scoring it
  // would fail the gate forever. Report it, exclude it from the gate.
  if (labelSpace) {
    metrics.outOfLabelSpace = {};
    for (const [cls, v] of Object.entries(metrics.perClass)) {
      if (!labelSpace.has(cls)) {
        metrics.outOfLabelSpace[cls] = v;
        delete metrics.perClass[cls];
      }
    }
  }

  const summary = {
    benignFpRate: rate(
      Object.values(metrics.sets).reduce((s, x) => s + x.benign.flagged, 0),
      Object.values(metrics.sets).reduce((s, x) => s + x.benign.n, 0)
    ),
    attackRecall: rate(
      Object.values(metrics.sets).reduce((s, x) => s + x.attack.flagged, 0),
      Object.values(metrics.sets).reduce((s, x) => s + x.attack.n, 0)
    ),
  };
  metrics.summary = summary;

  if (UPDATE) {
    fs.mkdirSync(path.dirname(BASELINE_PATH), { recursive: true });
    const snapshot = { createdAt: new Date().toISOString(), summary, sets: {}, perClass: metrics.perClass };
    for (const [k, v] of Object.entries(metrics.sets)) {
      snapshot.sets[k] = {
        benign: { n: v.benign.n, flagged: v.benign.flagged, fpRate: v.benign.fpRate, wrapperFp: v.benign.wrapperFp || 0, byType: v.benign.byType },
        attack: { n: v.attack.n, flagged: v.attack.flagged, recall: v.attack.recall },
      };
    }
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(snapshot, null, 2));
    console.log(`check:model: baseline written -> ${path.relative(ROOT, BASELINE_PATH)}`);
  }

  if (AS_JSON) {
    console.log(JSON.stringify(metrics, null, 2));
  } else {
    console.log(`\n=== cross-domain detection (chunk=${CHUNK}) ===`);
    for (const [k, v] of Object.entries(metrics.sets)) {
      console.log(`  ${k}`);
      console.log(`     benign  n=${String(v.benign.n).padStart(5)}  flagged=${String(v.benign.flagged).padStart(5)}  FP=${(v.benign.fpRate * 100).toFixed(1)}%` +
        (v.benign.byType && Object.keys(v.benign.byType).length ? `  [${Object.entries(v.benign.byType).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([t, c]) => `${t}x${c}`).join(', ')}]` : ''));
      if (v.benign.wrapperFp) console.log(`     SIEM-envelope false positives: ${v.benign.wrapperFp}`);
      console.log(`     attack  n=${String(v.attack.n).padStart(5)}  flagged=${String(v.attack.flagged).padStart(5)}  recall=${(v.attack.recall * 100).toFixed(1)}%`);
    }
    console.log(`  pooled benign FP=${(summary.benignFpRate * 100).toFixed(2)}%  attack recall=${(summary.attackRecall * 100).toFixed(2)}%`);
    console.log('  per-class recall: ' + Object.entries(metrics.perClass)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([c, v]) => `${c}=${(v.recall * 100).toFixed(0)}%(n=${v.n})`).join(' '));
    if (metrics.outOfLabelSpace && Object.keys(metrics.outOfLabelSpace).length) {
      console.log('  labels absent from the deployed model (excluded from the gate): ' +
        Object.entries(metrics.outOfLabelSpace).map(([c, v]) => `${c}(n=${v.n})`).join(' '));
    }
  }

  // ── gate ──────────────────────────────────────────────────────────────
  const failures = [...metrics.problems];
  if (summary.benignFpRate > MAX_BENIGN_FP_RATE) {
    failures.push(`benign FP rate ${(summary.benignFpRate * 100).toFixed(1)}% exceeds the ${MAX_BENIGN_FP_RATE * 100}% sanity bar`);
  }

  let baseline = null;
  try { baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8')); } catch { /* first run */ }
  if (baseline && !UPDATE) {
    const TOL = 0.02; // 2 points of slack, so noise doesn't flap the gate
    if (summary.benignFpRate > baseline.summary.benignFpRate + TOL) {
      failures.push(`benign FP rate regressed: ${(baseline.summary.benignFpRate * 100).toFixed(2)}% -> ${(summary.benignFpRate * 100).toFixed(2)}%`);
    }
    if (summary.attackRecall < baseline.summary.attackRecall - TOL) {
      failures.push(`attack recall regressed: ${(baseline.summary.attackRecall * 100).toFixed(2)}% -> ${(summary.attackRecall * 100).toFixed(2)}%`);
    }
    for (const [cls, v] of Object.entries(metrics.perClass)) {
      const b = (baseline.perClass || {})[cls];
      if (!b || !b.n) continue;
      const before = b.recall, after = v.recall;
      if (after < before - TOL) {
        failures.push(`per-class recall regressed for ${cls}: ${(before * 100).toFixed(0)}% -> ${(after * 100).toFixed(0)}% (n=${v.n})`);
      }
    }
  }

  if (failures.length) {
    console.error(`\ncheck:model FAILED (${failures.length}):`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log(`\ncheck:model OK${baseline && !UPDATE ? ' (no regression vs baseline)' : ''}`);
}

main().catch((e) => { console.error('check:model ERROR:', e); process.exit(1); });
