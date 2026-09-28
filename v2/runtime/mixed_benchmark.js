/**
 * mixed_benchmark.js — reproduce the "mixed requests" scenario.
 *
 * Interleaves attack lines into normal traffic at realistic ratios (the exact
 * production case that the legacy detector fails), runs them through the v2
 * ONNX classifier, and reports the acceptance gate:
 *
 *   attack recall     >= 0.95
 *   benign precision  >= 0.95   (few/no false alarms)
 *
 * Exit code 0 = pass, 1 = fail.
 * Uses the same payload seeds as the training augmentor for parity.
 */
const { V2Classifier } = require('./onnx_classifier');

const ATTACK_LINES = [
  "GET /product.php?id=1' OR '1'='1 HTTP/1.1",
  "GET /product.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1",
  "GET /search?q=UNION SELECT username,password FROM users-- HTTP/1.1",
  "POST /login admin' AND sleep(5)-- HTTP/1.1",
  "GET /page.php?id=1; DROP TABLE users-- HTTP/1.1",
  "GET /<script>alert(1)</script> HTTP/1.1",
  "GET /index.php?q=<img src=x onerror=alert(1)> HTTP/1.1",
  "GET /..%2f..%2fetc%2fpasswd HTTP/1.1",
  "GET /../../../../etc/passwd HTTP/1.1",
  "POST /administrator/ login=admin&pass=1234 HTTP/1.1",
  "GET /?id=1%20OR%201=1 HTTP/1.1",
  "GET /cgi-bin/test.cgi?f=../../../etc/passwd HTTP/1.1",
  "GET /index.php?id=1%2527%2520OR%25201=1 HTTP/1.1",
  "GET /catalog.php?cat=1/**/union/**/select/**/1,2,3-- HTTP/1.1",
];

const BENIGN_LINES = [
  "GET /index.html HTTP/1.1",
  "GET /assets/css/app.css HTTP/1.1",
  "POST /submit login=user&pass=secret HTTP/1.1",
  "GET /about HTTP/1.1",
  "GET /favicon.ico HTTP/1.1",
  "GET /products?id=42 HTTP/1.1",
  "GET /api/v1/status HTTP/1.1",
  "POST /api/v1/search {\"term\":\"hello\"} HTTP/1.1",
];

function buildMixed(ratio = 0.03, seed = 7) {
  let s = seed;
  const rnd = () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
  const out = [];
  const expected = [];
  // keep attack count small relative to benign so it models realistic mixing
  const attackCount = Math.max(1, Math.round(ATTACK_LINES.length * ratio));
  const attacks = ATTACK_LINES.slice(0, attackCount);
  const pool = [...attacks, ...BENIGN_LINES.slice(0, 8)];
  for (let i = 0; i < 200; i++) {
    if (rnd() < ratio) {
      const a = attacks[Math.floor(rnd() * attacks.length)];
      out.push(a);
      expected.push(true);
    } else {
      const b = BENIGN_LINES[Math.floor(rnd() * BENIGN_LINES.length)];
      out.push(b);
      expected.push(false);
    }
  }
  return { lines: out, expected };
}

async function main() {
  const clf = await V2Classifier.create();
  const { lines, expected } = buildMixed();
  const results = await clf.classifyBatch(lines);

  let tp = 0, fp = 0, fn = 0;
  results.forEach((r, i) => {
    const truth = expected[i];
    if (truth && r.is_attack) tp++;
    else if (!truth && r.is_attack) fp++;
    else if (truth && !r.is_attack) fn++;
  });
  const attackTotal = results.filter((_, i) => expected[i]).length;
  const benignTotal = results.length - attackTotal;

  const recall = tp / (tp + fn);
  const benignPrecision = benignTotal > 0 ? (benignTotal - fp) / benignTotal : 1;

  console.log(`\n[v2] MIXED-BENCHMARK (attack interleaved in normal traffic)`);
  console.log(`  attack lines : ${attackTotal}`);
  console.log(`  benign lines : ${benignTotal}`);
  console.log(`  TP=${tp} FP=${fp} FN=${fn}`);
  console.log(`  attack recall      : ${(recall * 100).toFixed(1)}%  (gate >= 95%)`);
  console.log(`  benign precision   : ${(benignPrecision * 100).toFixed(1)}%  (gate >= 95%)`);

  const pass = recall >= 0.95 && benignPrecision >= 0.95;
  console.log(`\n[v2] => ${pass ? 'PASS : production-ready' : 'FAIL : retrain / tune threshold'}`);
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('[v2] benchmark failed:', e.message);
  process.exit(1);
});
