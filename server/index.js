const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// Load environment config first
const config = require('./config/app.config');
const logger = require('./utils/logger');

// Middleware
const requestTimer = require('./middleware/requestTimer');
const responseFormatter = require('./middleware/responseFormatter');
const { errorHandler } = require('./middleware/errorHandler');
const { generalRateLimiter } = require('./middleware/rateLimiter');

// Routes
const logRoutes = require('./routes/logRoutes');
const aiRoutes = require('./routes/aiRoutes');

// Services
const preprocessor = require('./services/preprocessor');
const logStore = require('./store/logStore');
const aiClient = require('./ai/aiClient');

// Initialize Express app
const app = express();

// ─── MIDDLEWARE STACK (order matters) ────────────────────────────────────────

// 1. Request timer — must be first to capture full processing time
app.use(requestTimer);

// 2. CORS — strictly allow the Vercel frontend origin
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// 3. Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// 4. General rate limiting
app.use(generalRateLimiter);

// 5. Response formatter — adds res.success() and res.error() helpers
app.use(responseFormatter);

// ─── ROUTES ─────────────────────────────────────────────────────────────────

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

// Log management routes
app.use('/api', logRoutes);

// AI feature routes
app.use('/api/ai', aiRoutes);

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
      logger.info(`AI configured: ${aiClient.getInfo().provider} / ${aiClient.getInfo().model}`);
    } else {
      logger.warn('AI not configured — set NVIDIA_API_KEY in .env to enable AI features');
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
