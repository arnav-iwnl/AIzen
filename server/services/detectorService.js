const rules = require('../rules/logRules');
const mlModel = require('../ml/model');
const classificationService = require('./classificationService');
const config = require('../config/app.config');
const logger = require('../utils/logger');
const v2Bridge = require('../ml/v2Bridge');
const v2Detections = require('../ml/v2Detections');

// Per-IP nginx error tracking for scan detection
const nginxErrorTracker = new Map();

function trackNginxError(ip, signal, count = 1) {
  if (!ip) return null;
  const now = Date.now();
  let tracker = nginxErrorTracker.get(ip);
  if (!tracker || now - tracker.lastReset > 5 * 60 * 1000) {
    tracker = { upstreamFailures: 0, sslFailures: 0, lastReset: now };
    nginxErrorTracker.set(ip, tracker);
  }
  if (signal === 'NGINX_UPSTREAM_FAILURE' || signal === 'NGINX_UPSTREAM_TIMEOUT') {
    tracker.upstreamFailures += count;
  } else if (signal === 'NGINX_SSL_HANDSHAKE_FAILURE') {
    tracker.sslFailures += count;
  }
  return tracker;
}

// ponytail: dedup collapses identical lines, so floods are weighted by
// occurrenceCount; calendar 5-min window, not sliding. Refine with per-line
// timestamp bucketing if flood FPs matter.

function checkNginxScanFlags(tracker) {
  const flags = [];
  if (tracker.upstreamFailures >= 10) {
    flags.push('NGINX_UPSTREAM_SCAN_SUSPECTED');
  }
  if (tracker.sslFailures >= 3) {
    flags.push('NGINX_SSL_SCAN_SUSPECTED');
  }
  return flags;
}

function buildInsight(category, severity, count) {
  const base = {
    Security: 'Potential security event - inspect source and block if malicious.',
    Error: 'Operational failure affecting request processing.',
    Warning: 'Non-critical anomaly that may precede failures.',
    'Request Processing': 'Normal request traffic.',
    'Resource Not Found': 'Requests hitting missing resources (404s).',
    Startup: 'Service initialization activity.',
    Shutdown: 'Service termination activity.',
    Configuration: 'Configuration changes being applied.',
    'Worker Initialization': 'Worker/child process lifecycle.',
    'Backend Communication': 'Backend/upstream communication event.',
    Performance: 'Performance concern - investigate latency/resource usage.',
    Network: 'Network-level anomaly.',
    'Service Instability': 'Possible cascading failure - investigate immediately.',
  };
  const hint = base[category] || `Pattern occurs ${count}x.`;
  if (severity === 'critical' || severity === 'high') return `${hint} [${severity.toUpperCase()} priority]`;
  return hint;
}

/**
 * Detector Service - local, synchronous classification of log patterns.
 * Replaces the LLM API in the classify path (mode = "local").
 * Blends deterministic rules with the trained ML model.
 */
class DetectorService {
  async classify(patterns, startTime = Date.now()) {
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
      if (securityTags.length > 0 && category === 'Security') {
        insight = `Security signal: ${securityTags.join(', ')}. Review immediately.`;
      }

      if (pattern.source === 'nginx-error' || pattern.message?.startsWith('nginx error:')) {
        const ip = pattern.ip || (pattern.raw?.match(/client:\s*(\S+)/)?.[1]);
        if (ip) {
          const nginxSignals = ruleResult.securityTypes.filter(s => s.startsWith('NGINX_'));
          nginxSignals.forEach(sig => trackNginxError(ip, sig, pattern.occurrenceCount || 1));
          const scanFlags = checkNginxScanFlags(nginxErrorTracker.get(ip) || { upstreamFailures: 0, sslFailures: 0, lastReset: Date.now() });
          if (scanFlags.length > 0) {
            securityTags.push(...scanFlags);
            const upstreamHealth = scanFlags.includes('NGINX_UPSTREAM_SCAN_SUSPECTED') ? ' Investigate upstream health.' : '';
            insight = `Nginx scan suspected: ${scanFlags.join(', ')}.${upstreamHealth} ${insight}`;
            if (category !== 'Security') {
              category = 'Warning';
              severity = 'warning';
            }
          }
        }
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

    if (v2Bridge.isEnabled()) {
      v2Detections.clear();
      const texts = patterns.map((p) => (p.message && p.message.trim()) ? p.message : (p.raw || p.message || ''));
      const V2_CHUNK = 512;
      const results = [];
      for (let i = 0; i < texts.length; i += V2_CHUNK) {
        results.push(...(await v2Bridge.classifyBatch(texts.slice(i, i + V2_CHUNK))));
      }
      results.forEach((v2, j) => {
        const r = allResults[j];
        const ruleSecurity = r.securityTypes.length > 0;
        const v2Attack = !!(v2 && v2.is_attack);

        if (!ruleSecurity && !v2Attack) return;

        const priorTypes = r.securityTypes;
        let finalCategory = r.classification.category;
        let finalSeverity = r.classification.severity;
        let finalConfidence = r.classification.confidence;
        let finalExplanation = r.classification.explanation;
        let finalInsight = r.classification.insight;

        if (ruleSecurity && v2Attack) {
          finalConfidence = Math.min(99, Math.max(finalConfidence, Math.round(v2.attack_confidence * 100)));
          finalExplanation = `rule+v2:${v2.attack_type}`;
          finalInsight = `Deep classifier confirmed ${v2.attack_type} attack (${(v2.attack_confidence * 100).toFixed(1)}% confidence). Also matched: ${priorTypes.join(', ')}.`;
          r.securityTypes = Array.from(new Set([...priorTypes, v2.attack_type]));
        } else if (ruleSecurity && !v2Attack) {
          finalExplanation = `${finalExplanation} (v2 unsure)`;
          finalInsight = `${finalInsight} Deep classifier inconclusive.`;
        } else if (!ruleSecurity && v2Attack) {
          finalCategory = 'Security';
          finalSeverity = 'high';
          finalConfidence = Math.round(v2.attack_confidence * 100);
          finalExplanation = `v2:${v2.attack_type}`;
          finalInsight = `Deep classifier detected ${v2.attack_type} attack (${(v2.attack_confidence * 100).toFixed(1)}% confidence). No rule match.`;
          r.securityTypes = [v2.attack_type];
        }

        r.classification.category = finalCategory;
        r.classification.severity = finalSeverity;
        r.classification.confidence = finalConfidence;
        r.classification.explanation = finalExplanation;
        r.classification.insight = finalInsight;
        v2Detections.record(patterns[j].fingerprint, v2Attack ? v2.attack_type : 'rule', v2Attack ? v2.attack_confidence : 0);
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
      processingTimeMs: Date.now() - startTime,
      engine: 'local',
      usage: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
    };
  }
}

module.exports = new DetectorService();