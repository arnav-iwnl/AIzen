const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5000' || 'http://127.0.0.1:5000',
  vulnerableSiteUrl: process.env.VULNERABLE_SITE_URL || 'http://localhost:5173' || 'http://127.0.0.1:5173',
  // AI Configuration
  ai: {
    // Single API key for external LLM providers (OpenAI-compatible)
    apiKey: process.env.OPENAI_API_KEY || null,
    openaiBaseUrl: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1/chat/completions',
    defaultModel: process.env.AI_DEFAULT_MODEL || null,
    maxTokens: parseInt(process.env.LLM_MAX_TOKENS, 10) || 4096,
    temperature: 0.3,
    retryAttempts: 3,
    retryDelayMs: 1000,
  },

  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 20,
  },

  // Log Processing
  logProcessing: {
    maxLogLines: parseInt(process.env.MAX_LOG_LINES, 10) || 50000,
    contextWindowSize: parseInt(process.env.CONTEXT_WINDOW_SIZE, 10) || 100,
    classificationBatchSize: 150,
    timelineBatchSize: 1000,
    rootCauseBatchSize: 1000,
    timelineBucketMinutes: 15,
    rootCauseContextWindow: 5,
  },

  // Local ML Classifier (mode "local" replaces the LLM in the classify path)
  classifier: {
    mode: process.env.CLASSIFIER_MODE || 'local', // 'local' | 'llm'
    confidenceThreshold: parseInt(process.env.CLASSIFIER_CONFIDENCE_THRESHOLD, 10) || 70,
  },

  // Narrative generation (timeline/RCA): 'local' (default, no API) or 'llm'
  llmMode: process.env.LLM_MODE || 'local',

  // Incident Detection
  detection: {
    bucketMinutes: parseInt(process.env.DETECTION_BUCKET_MINUTES, 10) || 15,
    burstZThreshold: parseFloat(process.env.DETECTION_BURST_Z, 10) || 3,
    burstMinErrors: parseInt(process.env.DETECTION_BURST_MIN_ERRORS, 10) || 5,
    noveltyStartFraction: parseFloat(process.env.DETECTION_NOVELTY_START, 10) || 0.5,
    maxIncidents: parseInt(process.env.DETECTION_MAX_INCIDENTS, 10) || 20,
  },

  // AIzen v2 deep classifier (opt-in). Legacy pipeline stays identical unless
  // V2 classifier: enable when V2_CLASSIFIER=onnx OR when a local v2 runtime
  // model file exists at v2/runtime/model.onnx. We also expose modelPath.
  v2: {
    enabled: false,
    threshold: process.env.V2_THRESHOLD ? parseFloat(process.env.V2_THRESHOLD) : null,
    modelPath: null,
  },

  // Real-time SIEM (SSE hub)
  realtime: {
    bufferSize: parseInt(process.env.REALTIME_BUFFER_SIZE, 10) || 250,
    windowSeconds: parseInt(process.env.REALTIME_WINDOW_SECONDS, 10) || 60,
    errorAlertThreshold: parseInt(process.env.REALTIME_ERROR_ALERT_THRESHOLD, 10) || 15,
    securityAlertThreshold: parseInt(process.env.REALTIME_SECURITY_ALERT_THRESHOLD, 10) || 8,
    heartbeatMs: 15000,
  },

  // Demo traffic generator
  demo: {
    defaultRatePerSecond: parseFloat(process.env.DEMO_DEFAULT_RATE, 10) || 5,
    maxBurst: parseInt(process.env.DEMO_MAX_BURST, 10) || 200,
    poolSize: parseInt(process.env.DEMO_POOL_SIZE, 10) || 15,
  },

  // File Upload
  upload: {
    maxFileSizeMb: 200,
    allowedExtensions: ['.log', '.txt'],
  },

  // Telegram breach notifications (opt-in via env)
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN || null,
    channelId: process.env.TELEGRAM_CHANNEL_ID || null,
  },
};

const fs = require('fs');
// Path to potential local v2 ONNX model
const defaultV2ModelPath = require('path').resolve(__dirname, '../../v2/runtime/model.onnx');

// Auto-detect v2 model presence and enable if found or explicitly requested
const v2Requested = process.env.V2_CLASSIFIER === 'onnx';
if (v2Requested || fs.existsSync(defaultV2ModelPath)) {
  config.v2.enabled = true;
  config.v2.modelPath = fs.existsSync(defaultV2ModelPath) ? defaultV2ModelPath : null;
}

// In production we require explicit external URLs to be set to avoid
// inadvertently allowing requests from any origin. These should include
// the full origin including scheme, e.g. https://app.example.com
if (config.nodeEnv === 'production') {
  const missing = [];
  if (!config.frontendUrl) missing.push('FRONTEND_URL');
  if (!config.vulnerableSiteUrl) missing.push('VULNERABLE_SITE_URL');
  if (missing.length) {
    throw new Error(`Missing required environment variables for production: ${missing.join(', ')}`);
  }

  // Basic sanity check for origins
  const originRegex = /^https?:\/\/[A-Za-z0-9.-]+(?::\d+)?$/;
  if (!originRegex.test(config.frontendUrl) || !originRegex.test(config.vulnerableSiteUrl)) {
    throw new Error('FRONTEND_URL and VULNERABLE_SITE_URL must be valid origins, e.g. https://app.example.com');
  }
}

module.exports = config;
