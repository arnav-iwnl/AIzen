const rules = require('../rules/logRules');
const mlModel = require('../ml/model');
const classificationService = require('./classificationService');
const config = require('../config/app.config');
const logger = require('../utils/logger');

/**
 * Detector Service — local, synchronous classification of log patterns.
 * Replaces the LLM API in the classify path (mode = "local").
 * Blends deterministic rules with the trained ML model.
 */
class DetectorService {
  /**
   * Classify deduplicated patterns fully locally (no network).
   * @param {Object[]} patterns - deduped patterns (id, raw, level, message, occurrenceCount, firstSeen, lastSeen)
   * @returns {Object} Same response schema as the LLM classification endpoint
   */
  classify(patterns, startTime = Date.now()) {
    const threshold = config.classifier.confidenceThreshold || 70;
    const hasModel = mlModel.isLoaded();
    const allResults = [];

    for (const pattern of patterns) {
      const ruleResult = rules.classify({ message: pattern.message, level: pattern.level, raw: pattern.raw });
      const modelResult = mlModel.classifyMessage(pattern.message);

      let category = ruleResult.category;
      let severity = ruleResult.severity;
      let confidence = ruleResult.confidence;
      let explanation = `rule:${ruleResult.matchedRule || 'unknown'}`;
      let insight = buildInsight(category, severity, pattern.occurrenceCount || 1);

      // Model overrides rules when confident, unless rules flagged security.
      if (hasModel && modelResult) {
        if (ruleResult.securityTypes.length === 0 && modelResult.categoryConfidence >= threshold) {
          category = modelResult.category;
          severity = modelResult.severity;
          confidence = modelResult.categoryConfidence;
          explanation = 'ml:trained-classifier';
          insight = buildInsight(category, severity, pattern.occurrenceCount || 1);
        } else if (ruleResult.securityTypes.length > 0) {
          explanation = `rule:${ruleResult.matchedRule} (ml agreed: ${modelResult.category})`;
        }
      }

      const securityTags = ruleResult.securityTypes;
      if (securityTags.length > 0) {
        insight = `Security signal: ${securityTags.join(', ')}. Review immediately.`;
      }

      allResults.push({
        logId: pattern.id,
        originalLog: pattern.raw,
        timestamp: pattern.timestamp,
        sourceLevel: pattern.level,
        occurrenceCount: pattern.occurrenceCount,
        firstSeen: pattern.firstSeen || null,
        lastSeen: pattern.lastSeen || null,
        classification: {
          category,
          confidence,
          severity,
          explanation,
          insight,
        },
        securityTypes: securityTags,
      });
    }

    const processingTime = Date.now() - startTime;
    return {
      totalClassified: allResults.length,
      totalLogsRepresented: allResults.reduce((sum, r) => sum + (r.occurrenceCount || 1), 0),
      batchesProcessed: 1,
      classifications: allResults,
      summary: classificationService._buildSummary(allResults),
      categoryDistribution: classificationService._buildCategoryDistribution(allResults),
      processingTimeMs: processingTime,
      engine: 'local',
      usage: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }
}

function buildInsight(category, severity, count) {
  const base = {
    Security: 'Potential security event — inspect source and block if malicious.',
    Error: 'Operational failure affecting request processing.',
    Warning: 'Non-critical anomaly that may precede failures.',
    'Request Processing': 'Normal request traffic.',
    'Resource Not Found': 'Requests hitting missing resources (404s).',
    Startup: 'Service initialization activity.',
    Shutdown: 'Service termination activity.',
    Configuration: 'Configuration changes being applied.',
    'Worker Initialization': 'Worker/child process lifecycle.',
    'Backend Communication': 'Backend/upstream communication event.',
    Performance: 'Performance concern — investigate latency/resource usage.',
    Network: 'Network-level anomaly.',
    'Service Instability': 'Possible cascading failure — investigate immediately.',
  };
  const hint = base[category] || `Pattern occurs ${count}x.`;
  if (severity === 'critical' || severity === 'high') return `${hint} [${severity.toUpperCase()} priority]`;
  return hint;
}

module.exports = new DetectorService();
