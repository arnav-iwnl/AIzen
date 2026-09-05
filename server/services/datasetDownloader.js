/**
 * Dataset Downloader - downloads v2 model and training datasets at boot
 * if they are missing from disk. Uses a public bucket URL from env.
 *
 * Files managed:
 *   - v2/runtime/model.onnx
 *   v2/runtime/meta.json
 *   v2/datasets/web-attacks/hf.jsonl
 *   v2/datasets/http-attack-requests/hf.jsonl
 *   v2/datasets/web-attack-detection/hf.jsonl
 *   v2/datasets/malicious-urls/malicious-urls-dataset.zip (kaggle)
 *   v2/datasets/malicious-urls/malicious_phish.csv (extracted)
 *   data/access.log, test.log, Apache_2k.log, synthetic_error.log
 *
 * Usage: await ensureAll() from startServer() in index.js
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { extract } = require('tar');
const { createGunzip } = require('zlib');
const { pipeline } = require('stream/promises');

const config = require('../config/app.config');

const V2_ROOT = path.resolve(__dirname, '..');
const DATASETS_DIR = path.join(V2_ROOT, 'datasets');
const RUNTIME_DIR = path.join(V2_ROOT, 'runtime');
const DATA_DIR = path.join(V2_ROOT, 'data');

const REQUIRED_FILES = [
  // v2 runtime model
  { path: path.join(RUNTIME_DIR, 'model.onnx'), url: null }, // built from bucket
  { path: path.join(RUNTIME_DIR, 'meta.json'), url: null },
  // v2 training datasets
  { path: path.join(DATASETS_DIR, 'web-attacks', 'hf.jsonl'), url: null },
  { path: path.join(DATASETS_DIR, 'http-attack-requests', 'hf.jsonl'), url: null },
  { path: path.join(DATASETS_DIR, 'web-attack-detection', 'hf.jsonl'), url: null },
  { path: path.join(DATASETS_DIR, 'malicious-urls', 'malicious-urls-dataset.zip'), url: null },
  // data logs
  { path: path.join(DATA_DIR, 'access.log'), url: null },
  { path: path.join(DATA_DIR, 'test.log'), url: null },
  { path: path.join(DATA_DIR, 'Apache_2k.log'), url: null },
  { path: path.join(DATA_DIR, 'synthetic_error.log'), url: null },
];

const BUCKET_BASE = process.env.DATASET_BUCKET_URL;

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

async function downloadFile(url, destPath) {
  const dir = path.dirname(destPath);
  ensureDir(dir);

  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
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

async function extractZip(zipPath, destDir) {
  // For zip files, we use tar if it's a .tar.gz, otherwise we need unzip
  // For simplicity, we'll just ensure the file exists - extraction happens on demand
  return Promise.resolve();
}

async function ensureAll() {
  if (!BUCKET_BASE) {
    console.warn('[datasetDownloader] DATASET_BUCKET_URL not set — skipping dataset download');
    return;
  }

  console.log('[datasetDownloader] Checking and downloading missing assets...');

  for (const file of REQUIRED_FILES) {
    if (fs.existsSync(file.path)) {
      continue;
    }

    const url = BUCKET_BASE.replace(/\/$/, '') + '/' + path.relative(V2_ROOT, file.path).replace(/\\/g, '/');
    console.log(`[datasetDownloader] Downloading ${url} -> ${file.path}`);

    try {
      await downloadFile(url, file.path);
      console.log(`[datasetDownloader] Downloaded ${file.path}`);
    } catch (err) {
      console.warn(`[datasetDownloader] Failed to download ${url}: ${err.message}`);
      // Continue - v2 will gracefully degrade
    }
  }

  // Extract malicious-urls zip if needed
  const zipPath = path.join(DATASETS_DIR, 'malicious-urls', 'malicious-urls-dataset.zip');
  if (fs.existsSync(zipPath)) {
    // The CSV is extracted on first use by kaggle_ingest.py (unzip=True)
    console.log('[datasetDownloader] malicious-urls zip available');
  }

  console.log('[datasetDownloader] Done');
}

module.exports = { ensureAll };