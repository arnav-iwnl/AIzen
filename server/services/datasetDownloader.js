/**
 * Dataset Downloader - downloads the v2 runtime (and, optionally, the training
 * datasets) at boot if they are missing from disk.
 *
 * The runtime is CRITICAL: server/v2Bridge.js requires ../../v2/runtime/
 * onnx_classifier, which in turn requires ./tokenizer. Without all four runtime
 * files v2 silently degrades to disabled on a fresh clone or a Render deploy.
 * So these are always fetched, from a public default that needs no env var.
 *
 * The datasets are OPTIONAL and large (the web-attack-detection corpus alone is
 * ~178 MB), so they stay behind an explicit DATASET_BUCKET_URL.
 *
 * Files managed:
 *   v2/runtime/model.onnx, model.onnx.data, meta.json, tokenizer.js
 *   v2/datasets/web-attacks/hf.jsonl
 *   v2/datasets/http-attack-requests/hf.jsonl
 *   v2/datasets/web-attack-detection/hf.jsonl
 *   v2/datasets/malicious-urls/malicious-urls-dataset.zip (kaggle)
 *   data/access.log, test.log, Apache_2k.log, synthetic_error.log
 *
 * Usage: await ensureAll() from startServer() in index.js
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
// Use follow-redirects for reliable redirect handling (Hugging Face uses redirects)
let fhHttps;
try {
  fhHttps = require('follow-redirects').https;
} catch (e) {
  fhHttps = null;
}

const V2_ROOT = path.resolve(__dirname, '..');
const DATASETS_DIR = path.join(V2_ROOT, 'datasets');
const RUNTIME_DIR = path.join(V2_ROOT, 'runtime');
const DATA_DIR = path.join(V2_ROOT, 'data');

// Default source for the runtime. Public repo, so no env var is required to boot.
const RUNTIME_BASE = (process.env.V2_RUNTIME_BASE || 'https://huggingface.co/dr0wzy/aizen-siem/resolve/main')
  .replace(/\/+$/, '');
// Remote folder holding the CURRENT model. The repo also carries an older
// `runtime/` used as a fallback; pointing at that one by accident would silently
// serve a model that cannot emit half the MITRE labels, so the name is explicit.
const RUNTIME_REMOTE_DIR = (process.env.V2_RUNTIME_REMOTE_DIR || 'runtimev2').replace(/^\/+|\/+$/g, '');

// Normalize bucket base: trim trailing slashes to avoid double-slash issues
const BUCKET_BASE = process.env.DATASET_BUCKET_URL ? process.env.DATASET_BUCKET_URL.replace(/\/+$|\/$/g, '') : null;

// The four files the classifier cannot run without. model.onnx keeps its weights
// in an external .data sidecar, and tokenizer.js is required by onnx_classifier.js
// -- omitting either yields a model that downloads "successfully" and then fails
// to load.
// A runtime file smaller than this is not a model, it is a Git LFS pointer.
// v2/.gitattributes routes *.onnx through LFS but not *.onnx.data, so a clone
// made without LFS smuggled in resolves to a ~131-byte pointer for model.onnx
// and would pass an existence check while failing to load. Re-fetching anything
// this small repairs that, and also covers a truncated or half-written download.
// The smallest real artifact here is meta.json at 846 bytes, so the floor sits
// below it and above a pointer.
const MIN_RUNTIME_BYTES = 256;

const RUNTIME_FILES = ['model.onnx', 'model.onnx.data', 'meta.json', 'tokenizer.js'].map((name) => ({
  path: path.join(RUNTIME_DIR, name),
  url: `${RUNTIME_BASE}/${RUNTIME_REMOTE_DIR}/${name}`,
  minBytes: MIN_RUNTIME_BYTES,
}));

const DATASET_FILES = [
  { path: path.join(DATASETS_DIR, 'web-attacks', 'hf.jsonl'), url: null }, // built from bucket
  { path: path.join(DATASETS_DIR, 'http-attack-requests', 'hf.jsonl'), url: null },
  { path: path.join(DATASETS_DIR, 'web-attack-detection', 'hf.jsonl'), url: null },
  { path: path.join(DATASETS_DIR, 'malicious-urls', 'malicious-urls-dataset.zip'), url: null },
  // data logs
  { path: path.join(DATA_DIR, 'access.log'), url: null },
  { path: path.join(DATA_DIR, 'test.log'), url: null },
  { path: path.join(DATA_DIR, 'Apache_2k.log'), url: null },
  { path: path.join(DATA_DIR, 'synthetic_error.log'), url: null },
];

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

async function downloadFile(url, destPath) {
  const dir = path.dirname(destPath);
  ensureDir(dir);

  return new Promise((resolve, reject) => {
    const getter = fhHttps || https;
    const req = getter.get(url, { headers: { 'User-Agent': 'AIzen-Dataset-Downloader/1.0', Accept: '*/*' } }, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      const file = fs.createWriteStream(destPath);
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });
    req.on('error', reject);
  });
}

async function downloadAll(files, label) {
  const missing = files.filter((f) => {
    if (!fs.existsSync(f.path)) return true;
    if (f.minBytes && fs.statSync(f.path).size < f.minBytes) {
      console.warn(
        `[datasetDownloader] ${path.basename(f.path)} is only ${fs.statSync(f.path).size} bytes ` +
        '(Git LFS pointer or truncated) - re-fetching'
      );
      return true;
    }
    return false;
  });
  if (!missing.length) {
    console.log(`[datasetDownloader] ${label}: all ${files.length} files present`);
    return;
  }
  console.log(`[datasetDownloader] ${label}: ${missing.length}/${files.length} missing, downloading...`);
  for (const file of missing) {
    console.log(`[datasetDownloader] Downloading ${file.url}`);
    try {
      await downloadFile(file.url, file.path);
    } catch (err) {
      console.warn(`[datasetDownloader] Failed to download ${file.url}: ${err.message}`);
      // Continue - v2 will gracefully degrade
    }
  }
}

async function ensureAll() {
  // The runtime always: without it server/v2Bridge.js loads nothing and v2 is
  // silently disabled, which is exactly what a fresh clone / Render deploy hits.
  await downloadAll(RUNTIME_FILES, 'runtime');

  // Datasets only when explicitly configured - the corpora are hundreds of MB and
  // are needed for training, not for serving.
  if (BUCKET_BASE) {
    const withUrls = DATASET_FILES.map((f) => ({
      path: f.path,
      url: BUCKET_BASE + '/' + path.relative(V2_ROOT, f.path).replace(/\\/g, '/'),
    }));
    await downloadAll(withUrls, 'datasets');
  } else {
    console.warn('[datasetDownloader] DATASET_BUCKET_URL not set — skipping dataset download');
  }

  // The malicious-urls CSV is extracted on first use by kaggle_ingest.py
  // (unzip=True); here we only confirm the archive landed.
  const zipPath = path.join(DATASETS_DIR, 'malicious-urls', 'malicious-urls-dataset.zip');
  if (fs.existsSync(zipPath)) {
    console.log('[datasetDownloader] malicious-urls zip available');
  }

  console.log('[datasetDownloader] Done');
}

module.exports = { ensureAll };
