/**
 * TF-IDF vectorizer — replicates scikit-learn's TfidfVectorizer
 * (analyzer='char', sublinear_tf, L2 normalization) for JS inference.
 * The vocabulary/idf are loaded from the exported model.json.
 */
function buildIndex(vocab) {
  const index = new Map();
  for (let i = 0; i < vocab.length; i++) index.set(vocab[i], i);
  return index;
}

/**
 * Vectorize text into { scores: Map<column, tfidfWeight>, norm: L2Norm }.
 * @param {string} text
 * @param {Object} vec - model.vectorizer { ngram_range, sublinear_tf, vocab, idf }
 */
function vectorize(text, vec, index) {
  const chars = vec.lowercase === false ? text : text.toLowerCase();
  const [nMin, nMax] = vec.ngram_range;

  // Term frequencies over character ngrams
  const tf = new Map();
  for (let n = nMin; n <= nMax; n++) {
    for (let i = 0; i + n <= chars.length; i++) {
      const ng = chars.substring(i, i + n);
      tf.set(ng, (tf.get(ng) || 0) + 1);
    }
  }

  const scores = new Map();
  for (const [ng, count] of tf) {
    const col = index.get(ng);
    if (col === undefined) continue;
    const tfs = vec.sublinear_tf ? 1 + Math.log(count) : count;
    scores.set(col, tfs * vec.idf[col]);
  }

  let sq = 0;
  for (const w of scores.values()) sq += w * w;
  const norm = Math.sqrt(sq) || 1;

  return { scores, norm };
}

/**
 * Predict softmax probabilities from a precomputed vector against a head.
 * Used to run multiple heads (category + severity) on ONE vectorization.
 * @param {Object} vector - { scores, norm } from vectorize()
 * @param {Object} head - { classes, coef, intercept }
 * @returns {Object} { label, confidence, probabilities }
 */
function predictFromVector(vector, head) {
  const { scores, norm } = vector;

  const logits = head.classes.map((_, c) => {
    let s = head.intercept[c];
    const row = head.coef[c];
    for (const [col, w] of scores) s += row[col] * (w / norm);
    return s;
  });

  const max = Math.max(...logits);
  const exps = logits.map((l) => Math.exp(l - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  const probabilities = exps.map((e) => e / sum);

  let best = 0;
  for (let i = 1; i < probabilities.length; i++) {
    if (probabilities[i] > probabilities[best]) best = i;
  }

  return {
    label: head.classes[best],
    confidence: Math.round(probabilities[best] * 100),
    probabilities: Object.fromEntries(head.classes.map((c, i) => [c, probabilities[i]])),
  };
}

/**
 * Predict softmax probabilities for one text against a model head.
 * @param {string} text
 * @param {Object} head - { classes, coef, intercept }
 * @param {Object} vec
 * @returns {Object} { label, confidence, probabilities }
 */
function predictHead(text, head, vec, index) {
  return predictFromVector(vectorize(text, vec, index), head);
}

module.exports = { vectorize, predictHead, predictFromVector, buildIndex };
