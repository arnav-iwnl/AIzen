const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',

  // AI Configuration
  ai: {
    geminiApiKey: process.env.GEMINI_API_KEY,
    nvidiaApiKey: process.env.NVIDIA_API_KEY,
    openaiBaseUrl: process.env.OPENAI_BASE_URL || 'https://integrate.api.nvidia.com/v1/chat/completions',
    defaultModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
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
};

module.exports = config;
