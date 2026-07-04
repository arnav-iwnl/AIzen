const { z } = require('zod');
const { AppError } = require('./errorHandler');

/**
 * Schema Definitions for API request validation.
 */
const schemas = {
  // POST /api/ai/log-classification
  logClassification: z.object({
    logs: z.union([
      z.string().min(1, 'Log entry cannot be empty'),
      z.array(z.string().min(1)).min(1, 'At least one log entry is required').max(100, 'Maximum 100 log entries per request'),
    ]).optional(),
    model: z.string().optional(),
  }).optional(),

  // POST /api/ai/incident-timeline
  incidentTimeline: z.object({
    startTime: z.string().optional(),
    endTime: z.string().optional(),
    focus: z.enum(['errors', 'warnings', 'all']).optional().default('all'),
    maxEvents: z.number().int().min(1).max(50).optional().default(20),
    model: z.string().optional(),
  }).optional(),

  // POST /api/ai/root-cause-analysis
  rootCauseAnalysis: z.object({
    logIds: z.array(z.string()).optional(),
    timeRange: z.object({
      start: z.string(),
      end: z.string(),
    }).optional(),
    symptom: z.string().optional(),
    model: z.string().optional(),
  }).optional(),
};

/**
 * Create a validation middleware for a specific schema.
 * @param {string} schemaName - The key in the schemas object
 */
function validate(schemaName) {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) {
      return next(new AppError(`Unknown validation schema: ${schemaName}`, 500));
    }

    // For optional schemas (timeline, root-cause, classification), allow empty body
    if (!req.body || Object.keys(req.body).length === 0) {
      req.validatedBody = {};
      return next();
    }

    const result = schema.safeParse(req.body);
    if (!result.success) {
      const errors = result.error.errors.map((e) => ({
        field: e.path.join('.'),
        message: e.message,
      }));
      return res.error('Validation failed', 400, { errors });
    }

    req.validatedBody = result.data;
    next();
  };
}

module.exports = { validate, schemas };
