/**
 * onnx_classifier.js — in-process ONNX attack/category/severity classifier.
 *
 * Serves BOTH real-time (single line) and uploaded-log (batch) classification
 * with the same trained model, running on CPU via onnxruntime-node.
 * No Python, no GPU, no sidecar needed at runtime.
 *
 * Requires a trained artifact (v2/runtime/model.onnx + meta.json) produced by
 *   python -m export.export_onnx
 *
 * Usage:
 *   const { V2Classifier } = require('./onnx_classifier');
 *   const clf = await V2Classifier.create();           // loads once
 *   const r = clf.classifyLine('GET /..%2f..%2fetc%2fpasswd');   // realtime
 *   const rs = clf.classifyBatch([lines]);             // uploaded logs
 */
const fs = require('fs');
const path = require('path');
const { tokenize } = require('./tokenizer');

const ONNX_PATH = path.join(__dirname, 'model.onnx');
const META_PATH = path.join(__dirname, 'meta.json');

let ort = null;
try {
  ort = require('onnxruntime-node');
  // Suppress the static-output-shape verification warnings (harmless)
  if (ort && ort.env) ort.env.logSeverityLevel = 3; // ERROR only
} catch (e) {
  ort = null;
}

class V2Classifier {
  /**
   * @param {import('onnxruntime-node').InferenceSession} session
   * @param {Object} meta
   */
  constructor(session, meta) {
    this.session = session;
    this.meta = meta;
    this.maxLen = meta.max_len;
    this.noneIdx = meta.attack_index.none ?? 0;
    this.threshold = meta.attack_threshold ?? 0.5;
    this.attackThresholds = meta.attack_thresholds || {};
    this._inv = {};
    for (const [k, v] of Object.entries(meta.attack_index)) this._inv[v] = k;
    this._noneLabel = Object.keys(meta.attack_index).find((k) => meta.attack_index[k] === this.noneIdx) || 'none';
  }

  async initAll() {}

  static async create() {
    if (!ort) throw new Error('onnxruntime-node is not installed. Run: npm install (in v2/runtime)');
    if (!fs.existsSync(ONNX_PATH)) throw new Error(`No model at ${ONNX_PATH}. Run python -m export.export_onnx`);
    const meta = JSON.parse(fs.readFileSync(META_PATH, 'utf-8'));
    // 0 = all cores (fast local classification); set V2_THREADS=1 on tiny hosts.
    const threads = parseInt(process.env.V2_THREADS, 10) || 0;
    const session = await ort.InferenceSession.create(ONNX_PATH, {
      executionMode: 'sequential',
      intraOpNumThreads: threads,
      graphOptimizationLevel: 'all',
      logSeverityLevel: 3,
      logSeverityLevelDefault: 3,
    });
    return new V2Classifier(session, meta);
  }

  _toTensor(messages) {
    const data = new BigInt64Array(messages.length * this.maxLen);
    const dims = [messages.length, this.maxLen];
    for (let r = 0; r < messages.length; r++) {
      const ids = tokenize(messages[r], this.maxLen);
      const off = r * this.maxLen;
      for (let c = 0; c < this.maxLen; c++) data[off + c] = BigInt(ids[c]);
    }
    return new ort.Tensor('int64', data, dims);
  }

  _softmax(vec) {
    const m = Math.max(...vec);
    const ex = vec.map((x) => Math.exp(x - m));
    const s = ex.reduce((a, b) => a + b, 0);
    return ex.map((x) => x / s);
  }

  async _run(messages) {
    const feeds = { ids: this._toTensor(messages) };
    const out = await this.session.run(feeds);
    return out; // attack_logits, category_logits, severity_logits
  }

  /**
   * Single-line classification (real-time path).
   * @param {string} message
   */
  async classifyLine(message) {
    return (await this.classifyBatch([message]))[0];
  }

  /**
   * Batch classification (uploaded-logs path).
   * @param {string[]} messages
   */
  async classifyBatch(messages) {
    const out = await this._run(messages);
    // meta.<x>_index are plain objects ({label: idx}); .length is undefined.
    // Class count = highest index + 1 (indices are contiguous 0..N-1).
    const ncl = (map) => Object.values(map).reduce((mx, v) => Math.max(mx, v), 0) + 1;
    const A = ncl(this.meta.attack_index);
    const C = ncl(this.meta.category_index);
    const S = ncl(this.meta.severity_index);
    const aData = Array.from(out.attack_logits.data);
    const cData = Array.from(out.category_logits.data);
    const sData = Array.from(out.severity_logits.data);

    return messages.map((message, i) => {
      const at = this._softmax(aData.slice(i * A, i * A + A));
      const atIdx = at.indexOf(Math.max(...at));
      const attackType = this._inv[atIdx] ?? 'other';
      const attackConf = at[atIdx];
      const classThreshold = this.attackThresholds[attackType] ?? this._fallbackThreshold(attackType);
      const isAttack = atIdx !== this.noneIdx && attackConf >= classThreshold;
      const catArr = cData.slice(i * C, i * C + C);
      const catIdx = catArr.indexOf(Math.max(...catArr));
      const sevArr = sData.slice(i * S, i * S + S);
      const sevIdx = sevArr.indexOf(Math.max(...sevArr));
      return {
        message,
        is_attack: isAttack,
        attack_type: attackType,
        attack_confidence: attackConf,
        category: this._metaKey(this.meta.category_index, catIdx),
        severity: this._metaKey(this.meta.severity_index, sevIdx),
      };
    });
  }

  _metaKey(map, idx) {
    for (const [k, v] of Object.entries(map)) if (v === idx) return k;
    return 'unknown';
  }

  /**
   * Threshold for a class the meta file doesn't list.
   *
   * Silently falling back to the global threshold was a trap: that global value
   * is the STRICTEST bar in the file, so a newly trained class (a T#### id, say)
   * would inherit it and become effectively undetectable. The exporter now emits
   * an entry for every class, so reaching this is a real inconsistency worth
   * surfacing rather than absorbing.
   */
  _fallbackThreshold(attackType) {
    if (attackType === this._noneLabel) return this.threshold; // benign class: no bar to clear
    if (!this._warnedFallback) this._warnedFallback = new Set();
    if (!this._warnedFallback.has(attackType)) {
      this._warnedFallback.add(attackType);
      console.warn(
        `[v2] no attack_thresholds entry for "${attackType}" — using global ${this.threshold}. ` +
        'Re-run "python -m export.export_onnx" to regenerate per-class thresholds.'
      );
    }
    return this.threshold;
  }
}

module.exports = { V2Classifier };

// ── CLI ───────────────────────────────────────────────────────────────
if (require.main === module) {
  (async () => {
    const selfTest = process.argv.includes('--self-test');
    let clf;
    try {
      clf = await V2Classifier.create();
    } catch (e) {
      console.error(`[v2] classifier unavailable: ${e.message}`);
      process.exit(1);
    }
    if (selfTest) {
      const res = await clf.classifyLine('GET /..%2f..%2fetc%2fpasswd HTTP/1.1');
      console.log('[v2] self-test OK:', JSON.stringify(res));
      return;
    }
    const lines = process.argv.slice(2).length ? process.argv.slice(2) : [
      'GET /product?id=1%27%20OR%20%271%27=%271 HTTP/1.1',
      'GET /index.html HTTP/1.1',
    ];
    const start = Date.now();
    const results = await clf.classifyBatch(lines);
    console.log(`[v2] classified ${results.length} lines in ${Date.now() - start}ms`);
    for (const r of results) {
      console.log(`${r.is_attack ? 'ATTACK ' : 'OK     '} [${r.attack_type}] ${r.message}`);
    }
  })().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
