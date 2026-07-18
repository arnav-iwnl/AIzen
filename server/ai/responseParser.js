const logger = require('../utils/logger');

/**
 * LLM Response Parser
 * Handles the messy reality of LLM outputs:
 * - Strips markdown code fences
 * - Extracts JSON from mixed text
 * - Validates response structure
 * - Provides fallbacks for malformed responses
 */
class ResponseParser {
  /**
   * Parse an LLM response string into a JSON object.
   * Attempts multiple strategies to extract valid JSON.
   *
   * @param {string} responseText - Raw LLM response
   * @returns {Object|Array} Parsed JSON
   * @throws {Error} If JSON cannot be extracted
   */
  parse(responseText) {
    if (!responseText || typeof responseText !== 'string') {
      throw new Error('Empty or invalid response from AI');
    }

    let cleaned = responseText.trim();

    // Strategy 1: Try direct JSON.parse
    try {
      return JSON.parse(cleaned);
    } catch (e) {
      // Continue to next strategy
    }

    // Strategy 2: Strip markdown code fences (```json ... ``` or ``` ... ```)
    const codeFenceRegex = /```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/;
    const fenceMatch = cleaned.match(codeFenceRegex);
    if (fenceMatch) {
      try {
        return JSON.parse(fenceMatch[1].trim());
      } catch (e) {
        // Continue
      }
    }

    // Strategy 3: Find JSON object or array in the text
    const jsonObjectRegex = /(\{[\s\S]*\})/;
    const jsonArrayRegex = /(\[[\s\S]*\])/;

    // Try object first
    const objectMatch = cleaned.match(jsonObjectRegex);
    if (objectMatch) {
      try {
        return JSON.parse(objectMatch[1]);
      } catch (e) {
        // Continue
      }
    }

    // Try array
    const arrayMatch = cleaned.match(jsonArrayRegex);
    if (arrayMatch) {
      try {
        return JSON.parse(arrayMatch[1]);
      } catch (e) {
        // Continue
      }
    }

    // Strategy 4: Try to fix common JSON issues
    try {
      // Remove trailing commas
      const fixed = cleaned
        .replace(/,\s*([\]}])/g, '$1')
        // Fix single quotes
        .replace(/'/g, '"');
      return JSON.parse(fixed);
    } catch (e) {
      // Continue
    }

    // All strategies failed
    logger.error('Failed to parse AI response as JSON', {
      responsePreview: cleaned.substring(0, 200),
    });
    throw new Error('Failed to parse AI response as JSON. The AI returned an unexpected format.');
  }

  /**
   * Parse and validate a classification response.
   * @param {string} responseText - Raw LLM response
   * @returns {Object[]} Validated classification results
   */
  parseClassification(responseText) {
    const parsed = this.parse(responseText);
    const results = Array.isArray(parsed) ? parsed : parsed.classifications || parsed.results || [parsed];

    return results.map((item) => ({
      id: item.id || item.logId || 'unknown',
      category: item.category || item.classification || 'Unknown',
      confidence: typeof item.confidence === 'number' ? item.confidence : parseInt(item.confidence) || 0,
      severity: item.severity || 'medium',
      explanation: item.explanation || item.reason || item.description || 'No explanation provided',
      insight: item.insight || '',
    }));
  }

  /**
   * Parse and validate a timeline response.
   * @param {string} responseText - Raw LLM response
   * @returns {Object} Validated timeline
   */
  parseTimeline(responseText) {
    const parsed = this.parse(responseText);

    const timeline = parsed.timeline || parsed.events || parsed;
    const events = Array.isArray(timeline) ? timeline : [timeline];

    return {
      timeline: events.map((event) => ({
        timestamp: event.timestamp || event.time || 'Unknown',
        eventTitle: event.eventTitle || event.title || event.event || 'Unnamed Event',
        severity: event.severity || event.level || 'info',
        summary: event.summary || event.description || 'No summary',
        escalationPath: (event.escalationPath || event.escalation_path || []).map((step) => ({
          level: step.level || 'info',
          description: step.description || step.message || step.summary || '',
          timestamp: step.timestamp || step.time || '',
        })),
        supportingEvidence: event.supportingEvidence || event.evidence || event.logs || [],
        affectedComponents: event.affectedComponents || event.components || [],
      })),
      overallSummary: parsed.overallSummary || parsed.summary || 'Timeline generated from log data',
    };
  }

  /**
   * Parse and validate a root cause analysis response.
   * @param {string} responseText - Raw LLM response
   * @returns {Object} Validated RCA result
   */
  parseRootCause(responseText) {
    const parsed = this.parse(responseText);

    return {
      rootCause: parsed.rootCause || parsed.root_cause || 'Unable to determine root cause',
      evidence: (parsed.evidence || []).map((e) => ({
        finding: e.finding || e.observation || 'N/A',
        logPattern: e.logPattern || e.pattern || e.log || 'N/A',
        occurrences: e.occurrences || e.count || 0,
        significance: e.significance || e.importance || 'N/A',
      })),
      causalChain: parsed.causalChain || parsed.causal_chain || parsed.chain || [],
      impact: parsed.impact || 'Impact not assessed',
      recommendations: (parsed.recommendations || []).map((r) => ({
        action: r.action || r.recommendation || 'N/A',
        priority: r.priority || 'medium',
        rationale: r.rationale || r.reason || 'N/A',
      })),
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : parseInt(parsed.confidence) || 0,
      analysisNotes: parsed.analysisNotes || parsed.notes || null,
    };
  }
}

module.exports = new ResponseParser();
