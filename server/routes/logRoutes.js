const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
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
 * Decompress a .gz upload to a plain log file, then delete the archive.
 * @param {string} gzPath - path to the compressed file
 * @param {string} outPath - path to write the decompressed log
 */
function gunzipFile(gzPath, outPath) {
  return new Promise((resolve, reject) => {
    const gunzip = zlib.createGunzip();
    const src = fs.createReadStream(gzPath);
    const dest = fs.createWriteStream(outPath);
    src.pipe(gunzip).pipe(dest);
    gunzip.on('error', (err) => {
      try { fs.unlinkSync(outPath); } catch { /* ignore */ }
      reject(err);
    });
    dest.on('error', (err) => {
      try { fs.unlinkSync(outPath); } catch { /* ignore */ }
      reject(err);
    });
    dest.on('finish', () => {
      try { fs.unlinkSync(gzPath); } catch { /* ignore */ }
      resolve();
    });
  });
}

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
      let filePath = req.file.path;

      // Decompress gzip uploads (client compresses before POST to avoid
      // Render's CDN/WAF blocking bodies containing attack payloads).
      if (fileName.toLowerCase().endsWith('.gz')) {
        const plainPath = filePath.replace(/\.gz$/i, '');
        await gunzipFile(filePath, plainPath);
        filePath = plainPath;
        fileName = fileName.replace(/\.gz$/i, '');
      }

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
 * POST /api/load-generated
 * Load the generated v2 logs file (data/generated_v2_logs.log) into memory.
 */
router.post('/load-generated', async (req, res, next) => {
  try {
    const genPath = path.resolve(__dirname, '../../data/generated_v2_logs.log');

    if (!fs.existsSync(genPath)) {
      return res.error('Generated log file not found. Run server/scripts/generate_v2_logs.js to create it.', 404);
    }

    const content = fs.readFileSync(genPath, 'utf-8');
    const result = preprocessor.process(content, 'generated_v2_logs.log');

    logger.info('Generated v2 logs loaded', { totalLines: result.totalLines });
    return res.success(result, 'Generated v2 logs loaded successfully');
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
