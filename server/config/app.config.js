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
    classificationBatchSize: 25,
    timelineBucketMinutes: 15,
    rootCauseContextWindow: 5,
  },

  // File Upload
  upload: {
    maxFileSizeMb: 200,
    allowedExtensions: ['.log', '.txt'],
  },
};

module.exports = config;
