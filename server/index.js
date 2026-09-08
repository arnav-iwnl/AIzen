const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// Load environment config first
const config = require('./config/app.config');
const logger = require('./utils/logger');
const datasetDownloader = require('./services/datasetDownloader');

// Middleware
const requestTimer = require('./middleware/requestTimer');
const responseFormatter = require('./middleware/responseFormatter');
const { errorHandler } = require('./middleware/errorHandler');
const { generalRateLimiter } = require('./middleware/rateLimiter');

// Routes
const logRoutes = require('./routes/logRoutes');
const aiRoutes = require('./routes/aiRoutes');
const detectRoutes = require('./routes/detectRoutes');
const realtimeRoutes = require('./routes/realtimeRoutes');
const demoRoutes = require('./routes/demoRoutes');

// Services
const preprocessor = require('./services/preprocessor');
const logStore = require('./store/logStore');
const aiClient = require('./ai/aiClient');
const v2Bridge = require('./ml/v2Bridge');

// Initialize Express app
const app = express();

// ─── MIDDLEWARE STACK (order matters) ────────────────────────────────────────

// 1. Request timer — must be first to capture full processing time
app.use(requestTimer);

// 2. CORS — allow configured frontend and vulnerable-site origins.
let allowedOrigins = [config.frontendUrl, config.vulnerableSiteUrl].filter(Boolean);

// In non-production allow local dev origins for convenience
if (config.nodeEnv !== 'production') {
  allowedOrigins = allowedOrigins.concat([
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
  ]).filter(Boolean);
}

// Vercel-hosted frontend (aizen-siem) — allow even if FRONTEND_URL differs
allowedOrigins.push('https://aizen-siem.vercel.app');
allowedOrigins = [...new Set(allowedOrigins.filter(Boolean))];

app.use(cors({
  origin: (origin, callback) => {
    // Allow same-origin requests from tools (no origin) and allowed origins
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);

    callback(new Error(`CORS not allowed for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));
app.options('*', cors());
console.log('FRONTEND_URL:', config.frontendUrl);
console.log('VULNERABLE_SITE_URL:', config.vulnerableSiteUrl);
// 3. Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(generalRateLimiter);

// 5. Response formatter — adds res.success() and res.error() helpers
app.use(responseFormatter);
// Health check
app.get('/api/health', (req, res) => {
  res.success({
    status: 'healthy',
    uptime: process.uptime(),
    logsLoaded: logStore.isLoaded,
    aiConfigured: aiClient.isConfigured(),
    timestamp: new Date().toISOString(),
  }, 'AIzen server is running');
});

// Extended health check: includes v2 classifier readiness and model info
app.get('/api/health/extended', async (req, res, next) => {
  try {
    const v2Enabled = v2Bridge.isEnabled();
    let v2Loaded = false;
    let v2Info = null;
    if (v2Enabled) {
      const clf = await v2Bridge.get();
      v2Loaded = !!clf;
      v2Info = clf ? { threshold: clf.threshold || null } : null;
    }

    return res.success({
      status: 'healthy',
      uptime: process.uptime(),
      logsLoaded: logStore.isLoaded,
      aiConfigured: aiClient.isConfigured(),
      v2: { enabled: v2Enabled, loaded: v2Loaded, info: v2Info },
      timestamp: new Date().toISOString(),
    }, 'Extended health check');
  } catch (err) {
    next(err);
  }
});
// 4. General rate limiting




// ─── ROUTES ─────────────────────────────────────────────────────────────────



// Log management routes
app.use('/api', logRoutes);

// AI feature routes
app.use('/api/ai', aiRoutes);

// Local incident detection routes
app.use('/api/detect', detectRoutes);

// Real-time SIEM (SSE) + demo traffic generator
app.use('/api/realtime', realtimeRoutes);
app.use('/api/demo', demoRoutes);
app.use('/api/demo-dataset', require('./routes/datasetDemoRoutes'));

// ─── ERROR HANDLING ─────────────────────────────────────────────────────────

// 404 handler
app.use((req, res) => {
  res.error(`Route not found: ${req.method} ${req.path}`, 404);
});

// Global error handler (must be last)
app.use(errorHandler);




// ─── SERVER STARTUP ─────────────────────────────────────────────────────────

async function startServer() {
  try {
    // Download v2 model and training datasets if missing
    await datasetDownloader.ensureAll();

    // Pre-load the default Apache log file if it exists
    const defaultLogPath = path.resolve(__dirname, '../data/Apache_2k.log');
    if (fs.existsSync(defaultLogPath)) {
      logger.info('Pre-loading default Apache log file...');
      const content = fs.readFileSync(defaultLogPath, 'utf-8');
      const result = preprocessor.process(content, 'Apache_2k.log');
      logger.info(`Default logs loaded: ${result.parsedLines} entries, ${result.uniquePatterns} unique patterns`);
    } else {
      logger.warn('Default log file not found at data/Apache_2k.log — logs can be uploaded via API');
    }

    // Check AI configuration
    if (aiClient.isConfigured()) {
      logger.info(`AI configured: ${aiClient.getInfo().provider} / ${aiClient.getInfo().defaultModel || 'n/a'}`);
    } else {
      logger.warn('AI not configured — set OPENAI_API_KEY in .env to enable AI features');
    }

    // v2 deep classifier status
    try {
      logger.info(`v2 classifier enabled: ${config.v2.enabled} ${config.v2.modelPath ? `(${config.v2.modelPath})` : ''}`);
    } catch (e) {
      logger.debug('v2 status not available');
    }

    // Start listening
    app.listen(config.port, () => {
      logger.info(`🚀 AIzen server running on http://localhost:${config.port}`);
      logger.info(`   Environment: ${config.nodeEnv}`);
      logger.info(`   API Base: http://localhost:${config.port}/api`);
      logger.info(`   Health: http://localhost:${config.port}/api/health`);
    });
  } catch (error) {
    logger.error('Failed to start server', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}

startServer();

module.exports = app;
