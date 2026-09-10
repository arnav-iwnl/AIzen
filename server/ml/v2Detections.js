/**
 * v2Detections — in-memory record of fingerprints the v2 deep classifier
 * flagged as attacks during the last classification pass.
 *
 * Timeline/RCA run as separate requests after classification; this registry
 * lets them surface the deep model's verdict without re-running ONNX.
 * Volatile by design (process-scoped, cleared on each new classification).
 */
const flagged = new Map(); // fingerprint -> { attack_type, confidence, ts }

function record(fingerprint, attackType, confidence) {
  if (!fingerprint) return;
  flagged.set(fingerprint, {
    attack_type: attackType,
    confidence: confidence,
    ts: new Date().toISOString(),
  });
}

function get(fingerprint) {
  return flagged.get(fingerprint) || null;
}

function clear() {
  flagged.clear();
}

function size() {
  return flagged.size;
}

module.exports = { record, get, clear, size };