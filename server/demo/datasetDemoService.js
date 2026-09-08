/**
 * Dataset demo service - streams real traffic for the standalone /demo page.
 *
 * Two sources, drawn through the SAME pipeline (rules + v2) that the rest of
 * the app uses, so the page shows genuine live breach detection:
 *   1. data/*.log             - real parsed log lines (access.log, test.log, ...)
 *   2. v2/datasets hf.jsonl   - the actual v2 training corpora
 *      (http-attack-requests HF, web-attacks HF, web-attack-detection HF,
 *       malicious-urls Kaggle)
 *
 * Every emitted line is classified via realtimeHub.ingestLine (rules + v2) and
 * anything flagged as an attack is also surfaced as a v2 breach event.
 */
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const realtimeHub = require('../realtime/realtimeHub');
const v2Bridge = require('../ml/v2Bridge');
const config = require('../config/app.config');
const logger = require('../utils/logger');

const DATA_DIR = path.resolve(__dirname, '../../data');
const V2_DATASETS_DIR = path.resolve(__dirname, '../../v2/datasets');

const LOG_FILES = ['access.log', 'test.log', 'Apache_2k.log', 'synthetic_error.log'];

// Human label for each dataset source (used in the demo UI).
const DATASET_META = [
  { id: 'web-attacks', label: 'v2 - web-attacks (HF)', files: ['web-attacks/hf.jsonl'] },
  { id: 'http-attack-requests', label: 'v2 - http-attack-requests (HF)', files: ['http-attack-requests/hf.jsonl'] },
  { id: 'web-attack-detection', label: 'v2 - web-attack-detection (HF)', files: ['web-attack-detection/hf.jsonl'] },
  { id: 'malicious-urls', label: 'v2 - malicious-urls (Kaggle)', files: ['malicious-urls/malicious_phish.csv'] },
];

// Stream a file lazily and return non-empty lines (the web-attack-detection
// corpus is ~180MB, so we cap the read to avoid loading everything).
function readLines(fullPath, max = 20000) {
  return new Promise((resolve) => {
    const lines = [];
    const rl = readline.createInterface({ input: fs.createReadStream(fullPath, { encoding: 'utf8' }), crlfDelay: Infinity });
    rl.on('line', (line) => {
      if (lines.length >= max) { rl.close(); return; }
      const t = (line || '').trim();
      if (t) lines.push(t);
    });
    rl.on('close', () => resolve(lines));
    rl.on('error', () => resolve(lines));
  });
}

class DatasetDemoService {
  constructor() {
    this.caches = new Map(); // source id -> array of raw lines
    this.streamTimer = null;
    this.state = { running: false, source: 'mixed', rate: 5 };
  }

  getSources() {
    const sources = [
      { id: 'mixed', label: 'Mixed (logs + datasets)' },
      { id: 'logs', label: 'data/ logs' },
    ];
    for (const m of DATASET_META) sources.push({ id: m.id, label: m.label });
    return sources;
  }

  /** Load (cached) raw sample lines for a data source. */
  async loadSource(id) {
    if (this.caches.has(id)) return this.caches.get(id);

    let lines = [];
    if (id === 'logs' || id === 'mixed') {
      for (const file of LOG_FILES) {
        const p = path.join(DATA_DIR, file);
        if (!fs.existsSync(p)) continue;
        try {
          lines = lines.concat(await readLines(p, 3000));
        } catch { /* skip unreadable */ }
      }
    }
    if (id === 'mixed' || DATASET_META.some((m) => m.id === id)) {
      const meta = DATASET_META.find((m) => m.id === id);
      for (const rel of meta ? meta.files : []) {
        const p = path.join(V2_DATASETS_DIR, rel);
        if (!fs.existsSync(p)) continue;
        try {
          lines = lines.concat(await this._parseDatasetFile(p));
        } catch { /* skip */ }
      }
    }

    this.caches.set(id, lines);
    logger.info(`[dataset-demo] source '${id}' loaded: ${lines.length} lines`);
    return lines;
  }

  /** Parse a single HF jsonl / Kaggle csv file into raw log-ish lines. */
  async _parseDatasetFile(fullPath) {
    const rawLines = await readLines(fullPath, 20000);
    const out = [];
    for (const line of rawLines) {
      if (fullPath.endsWith('.csv')) {
        // Kaggle: url,type  -> skip header, keep url
        const parts = line.split(',');
        if (parts[0] === 'url') continue;
        const url = parts[0];
        if (url && !out.includes(url)) out.push(url.trim().slice(0, 300));
        continue;
      }
      // HF jsonl: {"text": "...", "label": "..."}
      try {
        const obj = JSON.parse(line);
        if (obj && typeof obj.text === 'string') {
          const t = obj.text.trim().slice(0, 300);
          if (t) out.push(t);
        }
      } catch { /* skip malformed */ }
    }
    return out.slice(0, 15000);
  }

  _pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  _randomIP() {
    return `${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  }

  /** Wrap a bare payload (dataset sample) into a realistic Apache access line. */
  wrapAsLog(raw) {
    const ip = this._randomIP();
    const now = new Date();
    const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const p = (n) => String(n).padStart(2, '0');
    const ts = `${p(now.getUTCDate())}/${MONTHS[now.getUTCMonth()]}/${now.getUTCFullYear()}:${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())} +0000`;
    const ua = this._pick(['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'curl/8.5.0', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 'acunetix']);
    const pathPart = raw.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 240);
    return `${ip} - - [${ts}] "GET ${pathPart} HTTP/1.1" 200 512 "-" "${ua}"`;
  }

  /**
   * Fire `count` lines from the chosen source into the realtime hub.
   * Uses batch v2 classification when enabled for much faster throughput.
   * Returns { generated, attacks } where attacks is the number the v2/pipeline
   * classified as Security.
   */
  async trigger(count = 50) {
    const source = this.state.source || 'mixed';
    const lines = await this.loadSource(source);
    if (!lines.length) return { generated: 0, attacks: 0 };

    const safe = Math.min(Math.max(count, 1), config.demo.maxBurst);
    const rawLines = [];
    for (let i = 0; i < safe; i++) {
      const raw = this._pick(lines);
      rawLines.push(this.wrapAsLog(raw));
    }

    // Batch v2 classification — one ONNX inference for all lines
    const v2Results = v2Bridge.isEnabled()
      ? await v2Bridge.classifyBatch(rawLines)
      : rawLines.map(() => null);

    let generated = 0;
    let attacks = 0;
    for (let i = 0; i < rawLines.length; i++) {
      try {
        const ev = await realtimeHub.ingestLine(rawLines[i], `dataset:${source}`, v2Results[i]);
        if (ev) {
          generated++;
          if (ev.category === 'Security') attacks++;
        }
      } catch { /* skip */ }
    }
    return { generated, attacks };
  }

  startStream({ rate, source } = {}) {
    this.stopStream();
    const safeRate = Math.min(Math.max(parseFloat(rate) || 5, 0.5), 100);
    if (source) this.state.source = source;
    this.state.running = true;
    this.state.rate = safeRate;

    this.streamTimer = setInterval(() => {
      this.trigger(1).catch(() => {});
    }, Math.round(1000 / safeRate));

    return this.getStreamState();
  }

  stopStream() {
    if (this.streamTimer) clearInterval(this.streamTimer);
    this.streamTimer = null;
    this.state.running = false;
    return this.getStreamState();
  }

  getStreamState() {
    return { ...this.state, sources: this.getSources() };
  }
}

module.exports = new DatasetDemoService();
