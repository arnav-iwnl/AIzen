const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const preprocessor = require('../services/preprocessor');
const logStore = require('../store/logStore');
const logger = require('../utils/logger');
const config = require('../config/app.config');

const router = express.Router();

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file upload (disk storage for streaming)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: config.upload.maxFileSizeMb * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (config.upload.allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${ext}. Allowed: ${config.upload.allowedExtensions.join(', ')}`));
    }
  },
});

/**
 * POST /api/upload
 * Upload a log file and parse it into memory.
 */
router.post('/logs/upload', upload.single('logfile'), async (req, res, next) => {
  try {
    let result;
    let fileName;

    if (req.file) {
      // File uploaded via multipart form (saved to disk)
      fileName = req.file.originalname;
      const filePath = req.file.path;
      
      // Process the log file stream
      result = await preprocessor.processFileStream(filePath, fileName);
    } else if (req.body && req.body.content) {
      // Raw content sent in body (still supported for small manual uploads)
      const content = req.body.content;
      fileName = req.body.fileName || 'uploaded-log';
      result = await preprocessor.process(content, fileName);
    } else {
      return res.error('No log file or content provided. Send a file as "logfile" or raw content in body.', 400);
    }

    logger.info(`Log file processed: ${fileName}`, {
      totalLines: result.totalLines,
      parsed: result.parsedLines,
    });

    return res.success(result, `Log file "${fileName}" processed successfully`);
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/load-default
 * Load the default Apache_2k.log file from the data directory.
 */
router.post('/load-default', async (req, res, next) => {
  try {
    const defaultLogPath = path.resolve(__dirname, '../../data/Apache_2k.log');

    if (!fs.existsSync(defaultLogPath)) {
      return res.error('Default log file (Apache_2k.log) not found in data directory.', 404);
    }

    const content = fs.readFileSync(defaultLogPath, 'utf-8');
    const result = preprocessor.process(content, 'Apache_2k.log');

    logger.info('Default log file loaded', { totalLines: result.totalLines });

    return res.success(result, 'Default Apache log file loaded successfully');
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/logs
 * Retrieve parsed logs (paginated).
 */
router.get('/logs', (req, res, next) => {
  try {
    if (!logStore.isLoaded) {
      return res.error('No logs loaded. Upload a log file first.', 400);
    }

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const level = req.query.level;

    let logs = level ? logStore.getByLevel(level) : logStore.logs;
    const total = logs.length;
    const totalPages = Math.ceil(total / limit);
    const offset = (page - 1) * limit;

    logs = logs.slice(offset, offset + limit);

    return res.success({
      logs,
      pagination: { page, limit, total, totalPages },
    }, `Retrieved ${logs.length} logs`);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/logs/stats
 * Get log statistics.
 */
router.get('/logs/stats', (req, res, next) => {
  try {
    if (!logStore.isLoaded) {
      return res.error('No logs loaded. Upload a log file first.', 400);
    }

    return res.success(logStore.getStats(), 'Log statistics retrieved');
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/logs/patterns
 * Get deduplicated log patterns.
 */
router.get('/logs/patterns', (req, res, next) => {
  try {
    if (!logStore.isLoaded) {
      return res.error('No logs loaded. Upload a log file first.', 400);
    }

    const deduped = logStore.getDeduped();
    return res.success({
      patterns: deduped,
      totalPatterns: deduped.length,
      totalLogs: logStore.stats.totalLogs,
    }, `Found ${deduped.length} unique log patterns`);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
