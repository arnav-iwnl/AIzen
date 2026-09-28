/**
 * Train/serve tokenizer parity gate.
 *
 * The char tokenizer existed in four copies (prep/tokenizer.py,
 * runtime/tokenizer.js, eval/eval_runner.py and a dead runtime/onnx_export.py
 * scaffold). They had already drifted: the eval copy truncated at [:MAX_LEN]
 * while the runtime kept the head only and Python kept the head only, and
 * Python iterates UTF-16 code units while JS iterates code points — so any
 * non-BMP character produced DIFFERENT token sequences in training and serving.
 *
 * This compares the two implementations that actually matter on a corpus of
 * awkward inputs: empty, over-long, multi-byte, and non-ASCII payloads.
 *
 * Run: npm run check:tokenizer
 */
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');
const { tokenize, PAD, UNK, BASE } = require(path.join(ROOT, 'v2/runtime/tokenizer.js'));

const MAX_LEN = 256;

const CASES = [
  '',
  'GET /index.html HTTP/1.1',
  'Failed password for invalid user admin from 10.0.0.5 port 22 ssh2',
  'Web server 500 error code (server error). 1.2.3.4 - - [09/Sep/2026:06:03:59 +0530] "GET /robots.txt HTTP/1.1" 502 552',
  // over the window: must keep BOTH ends
  'Network switch session ended for user wazuh->106.201.231.25 | Jan  1 00:06:16 : 131 %% Session 0 of type 2 ended for user NONE connected from 192.168.1.37 and then a very long tail '.repeat(6),
  'A'.repeat(MAX_LEN - 1),
  'A'.repeat(MAX_LEN),
  'A'.repeat(MAX_LEN + 1),
  'A'.repeat(MAX_LEN * 3),
  // multi-byte + non-BMP (astral plane -> surrogate pair in Python)
  'GET /café/menü?q=naïve HTTP/1.1',
  'attack \u{1F41E} target \u{1F4A3} done',
  'SELECT * FROM users WHERE name = "日本語"',
  'mixed CASE Upper lower 12345 %2e%2e%2f',
  'tab\tseparated\tvalues and "quotes" and \'apostrophes\'',
];

// The Python side is the training-time source of truth, so it is the reference.
const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(path.join(ROOT, 'v2'))})
from prep.tokenizer import CharTokenizer
cases = json.load(open(sys.argv[1], encoding='utf-8'))
tok = CharTokenizer(${MAX_LEN})
json.dump([tok.encode(c) for c in cases], open(sys.argv[2], 'w'))
`;

const tmpIn = path.join(require('os').tmpdir(), 'tok-parity-in.json');
const tmpOut = path.join(require('os').tmpdir(), 'tok-parity-out.json');
const tmpScript = path.join(require('os').tmpdir(), 'tok-parity.py');

require('fs').writeFileSync(tmpIn, JSON.stringify(CASES), 'utf8');
require('fs').writeFileSync(tmpScript, script, 'utf8');

const python = ['.venv/Scripts/python.exe', 'python'].find((p) => require('fs').existsSync(path.join(ROOT, p)));
if (!python) {
  console.error('check:tokenizer: no python interpreter found');
  process.exit(1);
}
try {
  execFileSync(path.join(ROOT, python), [tmpScript, tmpIn, tmpOut], { stdio: 'pipe' });
} catch (e) {
  console.error('check:tokenizer: python side failed:', e.stderr ? e.stderr.toString() : e.message);
  process.exit(1);
}

const pyIds = JSON.parse(require('fs').readFileSync(tmpOut, 'utf8'));
const jsIds = CASES.map((c) => tokenize(c, MAX_LEN));

let failures = 0;
CASES.forEach((c, i) => {
  const a = pyIds[i];
  const b = jsIds[i];
  const label = c.length > 46 ? JSON.stringify(c.slice(0, 43)) + `... (len ${c.length})` : JSON.stringify(c);
  if (a.length !== MAX_LEN || b.length !== MAX_LEN) {
    console.error(`  FAIL ${label}: length ${a.length}/${b.length}, expected ${MAX_LEN}`);
    failures++;
    return;
  }
  if (a.join(',') === b.join(',')) {
    const firstNonPad = a.find((x) => x !== PAD);
    console.log(`  ok  ${label} -> ${firstNonPad === UNK ? 'UNK-heavy' : 'id ' + firstNonPad}, ${a.filter((x) => x !== PAD).length} real tokens`);
  } else {
    const at = a.findIndex((x, k) => x !== b[k]);
    console.error(`  FAIL ${label}: diverges at index ${at} (python=${a[at]} js=${b[at]})`);
    failures++;
  }
});

if (failures) {
  console.error(`\ncheck:tokenizer FAILED (${failures}/${CASES.length}) — train and serve would disagree.`);
  process.exit(1);
}
console.log('\ncheck:tokenizer OK — Python and JS tokenizers agree on all cases (head+tail window).');
