/**
 * Character tokenizer for the Node runtime.
 * Must mirror v2/prep/tokenizer.py exactly so train/serve agree.
 * `npm run check:tokenizer` asserts that parity.
 */
const PAD = 0;
const UNK = 1;
const BASE = 256;

/**
 * Keep the HEAD and the TAIL of an over-long string.
 *
 * Truncating at slice(0, maxLen) kept the SIEM envelope prefix and discarded
 * the payload, which for SIEM alerts is the part that carries the signal
 * (v2/ingest/ossec_ingest.py:147 builds "<alert desc> <body>").
 */
function window(text, maxLen) {
  if (text.length <= maxLen) return text;
  const head = Math.floor(maxLen / 2);
  return text.slice(0, head) + text.slice(-(maxLen - head));
}

function tokenize(text, maxLen) {
  const s = window((text || '').toString().toLowerCase(), maxLen);
  const ids = [];
  for (const ch of s) {
    const code = ch.codePointAt(0);
    ids.push(code < BASE ? code + 2 : UNK);
  }
  while (ids.length < maxLen) ids.push(PAD);
  ids.length = maxLen;
  return ids;
}

module.exports = { tokenize, window, PAD, UNK, BASE };
