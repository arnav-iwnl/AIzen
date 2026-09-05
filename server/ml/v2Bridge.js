/**
 * v2Bridge — lazy, opt-in bridge to the AIzen v2 deep ONNX classifier.
 *
 * When V2_CLASSIFIER=onnx the deep model is loaded once (in-process, CPU) and
 * used to augment both realtime and uploaded-log detection. When disabled (or
 * the model/artifacts are missing) every method resolves to a no-op, so the
 * legacy pipeline stays fully unchanged.
 */
const config = require('../config/app.config');

let clfPromise = null;

function isEnabled() {
  return !!(config.v2 && config.v2.enabled);
}

/**
 * Resolve the shared classifier instance (null when disabled/unavailable).
 * @returns {Promise<import('../../v2/runtime/onnx_classifier').V2Classifier|null>}
 */
function get() {
  if (!isEnabled()) return Promise.resolve(null);
  if (!clfPromise) {
    clfPromise = (async () => {
      const { V2Classifier } = require('../../v2/runtime/onnx_classifier');
      const clf = await V2Classifier.create();
      // honour an explicit threshold override
      if (config.v2.threshold != null) clf.threshold = config.v2.threshold;
      return clf;
    })().catch((err) => {
      clfPromise = null; // allow a retry on the next call
      return null;
    });
  }
  return clfPromise;
}

/**
 * Classify a single line with v2 (async). Returns null when disabled or when
 * the model is unavailable.
 * @param {string} message
 * @returns {Promise<Object|null>} { is_attack, attack_type, attack_confidence }
 */
async function classifyLine(message) {
  const clf = await get();
  if (!clf || !message) return null;
  try {
    const r = await clf.classifyLine(message);
    return {
      is_attack: !!r.is_attack,
      attack_type: r.attack_type,
      attack_confidence: r.attack_confidence,
    };
  } catch (err) {
    return null;
  }
}

module.exports = { get, isEnabled, classifyLine };
