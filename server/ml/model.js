/**
 * Model registry — loads the exported model.json (and optional attack.json)
 * and provides prediction on log patterns. No Python needed at runtime.
 */
const fs = require('fs');
const path = require('path');
const { vectorize, predictHead, buildIndex } = require('./vectorizer');
const logger = require('../utils/logger');

const MODEL_PATH = path.join(__dirname, 'model.json');
const ATTACK_PATH = path.join(__dirname, 'attack.json');

let model = null;
let attack = null;
let index = null;
let attackIndex = null;

function load() {
  if (model) return;
  if (!fs.existsSync(MODEL_PATH)) {
    logger.warn(`ML model not found at ${MODEL_PATH} — run "npm run train" (in server/).`);
    return;
  }
  model = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf-8'));
  index = buildIndex(model.vectorizer.vocab);
  logger.info(`ML model loaded: ${model.category.classes.length} categories, ${model.vectorizer.vocab.length} features`);

  if (fs.existsSync(ATTACK_PATH)) {
    attack = JSON.parse(fs.readFileSync(ATTACK_PATH, 'utf-8'));
    attackIndex = buildIndex(attack.vectorizer.vocab);
    logger.info(`Attack model loaded: ${attack.attack.classes.join('/')}`);
  }
}

function isLoaded() {
  return Boolean(model);
}

/**
 * Classify one pattern message with the trained model.
 * @param {string} text - normalized log message
 * @returns {Object|null} { category, categoryConfidence, severity, severityConfidence }
 */
function classifyMessage(text) {
  load();
  if (!model || !text) return null;

  const cat = predictHead(text, model.category, model.vectorizer, index);
  const sev = predictHead(text, model.severity, model.vectorizer, index);

  return {
    category: cat.label,
    categoryConfidence: cat.confidence,
    severity: sev.label,
    severityConfidence: sev.confidence,
  };
}

/**
 * Optional attack/normal scoring (trained from loghub OpenSSH labels).
 * @returns {Object|null} { label: 'normal'|'attack', confidence } or null if model absent
 */
function scoreAttack(text) {
  load();
  if (!attack || !text) return null;
  const res = predictHead(text, attack.attack, attack.vectorizer, attackIndex);
  return { label: res.label, confidence: res.confidence };
}

module.exports = { load, isLoaded, classifyMessage, scoreAttack };
