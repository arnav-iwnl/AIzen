/**
 * Log Rules — deterministic classification ruleset.
 *
 * Single source of truth used by:
 *  1. seedLabels.js     — auto-label training corpus
 *  2. detectorService.js — runtime rule fallback when no model / low confidence
 *
 * Operates on the NORMALIZED message text + level + HTTP status, so it is
 * format-agnostic (works for Apache, Nginx, syslog, JSON logs alike).
 */

const LEVEL_SEVERITY = {
  emerg: 'critical',
  alert: 'critical',
  crit: 'critical',
  critical: 'critical',
  error: 'high',
  err: 'high',
  warn: 'medium',
  warning: 'medium',
  notice: 'low',
  info: 'info',
  debug: 'info',
  unknown: 'medium',
};

const STATUS_SEVERITY = {
  500: 'critical',
  501: 'high',
  502: 'high',
  503: 'high',
  504: 'high',
  429: 'medium',
  401: 'medium',
  403: 'medium',
  404: 'low',
  400: 'medium',
  408: 'medium',
};

const STATUS_CATEGORY = {
  404: 'Resource Not Found',
  401: 'Security',
  403: 'Security',
};

// Security scanner / attack signatures (extracted from contextSelector)
const SECURITY_PATTERNS = [
  { type: 'SCANNER_SIGNATURE', regex: /(?:acunetix|nikto|sqlmap|nmap|wvstest|dirbuster)/i },
  { type: 'SQL_INJECTION', regex: /(?:['"]?\s*(?:OR|AND|UNION)\s+\d|SELECT\s+.*FROM|DROP\s+TABLE|--\s*$|%27|%22.*(?:OR|AND))/i },
  { type: 'XSS_PROBE', regex: /(?:<script|javascript:|onerror\s*=|onload\s*=|<xsstag>|domxss|<img\s+src)/i },
  { type: 'PATH_TRAVERSAL', regex: /(?:\/etc\/passwd|\.\.\/|\.\.\\|\/proc\/|\/var\/log)/i },
  { type: 'ADMIN_BRUTE_FORCE', regex: /(?:\/administrator\/|\/admin\/|\/wp-admin|\/login).*(?:POST|5\d{2})/i },
  { type: 'DIRECTORY_FORBIDDEN', regex: /(?:Directory index forbidden|forbidden by rule)/i },
  { type: 'CREDENTIAL_PROBE', regex: /(?:task=user\.login|task=registration|\/wp-login|auth|token)/i },
  { type: 'AUTH_FAILURE', regex: /(?:Failed password|authentication failure|invalid user|pam_authenticate|login attempt.*fail)/i },
];

// Ordered category rules — first match wins. Security first.
const CATEGORY_RULES = [
  {
    category: 'Security',
    severity: 'high',
    confidence: 92,
    regex: new RegExp(SECURITY_PATTERNS.map((s) => s.regex.source).join('|'), 'i'),
  },
  { category: 'Startup', severity: 'low', confidence: 88, regex: /(?:workerEnv\.init|start(?:ed|ing)? up|daemon start|listening on|server ready|begin.*init)/i },
  { category: 'Shutdown', severity: 'low', confidence: 88, regex: /(?:shutdown|graceful stop|SIGTERM|stopping|terminated|exit signal)/i },
  { category: 'Worker Initialization', severity: 'low', confidence: 88, regex: /(?:Found child|scoreboard slot|worker_init|child\s+\d+\s+spawn|forked)/i },
  { category: 'Configuration', severity: 'low', confidence: 85, regex: /(?:config|workers2\.properties|\.conf\b|rewrite|loadmodule|include\b)/i },
  { category: 'Backend Communication', severity: 'medium', confidence: 85, regex: /(?:mod_jk|jk2_init|tomcat|upstream|proxy|backend|workerEnv|ajp|connect\(\) failed)/i },
  { category: 'Performance', severity: 'medium', confidence: 88, regex: /(?:timeout|slow(?:ly)?|exhausted|too many|out of memory|connection limit|resource)/i },
  { category: 'Network', severity: 'medium', confidence: 85, regex: /(?:connection (?:reset|refused|closed)|dns|socket|unreachable|lookup failed|broken pipe)/i },
  { category: 'Resource Not Found', severity: 'low', confidence: 90, regex: /(?:no such file|does not exist|ENOENT|not found|404)/i },
  { category: 'Service Instability', severity: 'critical', confidence: 85, regex: /(?:restart loop|crash loop|repeated (?:failure|crash)|cascading|cannot recover)/i },
  { category: 'Request Processing', severity: 'info', confidence: 80, regex: /(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+/i },
];

// status code that appears after HTTP/1.x in either
//   "...HTTP/1.1" 200   (raw access log) or
//   "HTTP/1.1 - Status 200" (parser message form)
const METHOD_REGEX = /(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/1\.\d[^\d]*(\d{3})/i;

/**
 * Classify a log pattern deterministically.
 * @param {Object} opts - { message, level, raw }
 * @returns {Object} { category, severity, confidence, matchedRule, securityTypes }
 */
function classify(opts) {
  const message = opts.message || '';
  const raw = opts.raw || message;
  const level = (opts.level || '').toLowerCase();
  const text = `${raw} ${message}`;

  // HTTP status derived from access-log style messages
  let status = null;
  const statusMatch = text.match(METHOD_REGEX);
  if (statusMatch) status = parseInt(statusMatch[1], 10);

  const securityTypes = [];
  for (const { type, regex } of SECURITY_PATTERNS) {
    if (regex.test(text)) securityTypes.push(type);
  }

  let category = null;
  let severity = LEVEL_SEVERITY[level] || 'medium';
  let confidence = 80;
  let matchedRule = null;

  if (securityTypes.length > 0) {
    category = 'Security';
    severity = 'high';
    confidence = 92;
    matchedRule = `security:${securityTypes[0]}`;
  } else if (status) {
    if (status >= 500) {
      category = 'Error';
      severity = STATUS_SEVERITY[status] || 'high';
      matchedRule = `status:${status}`;
    } else if (STATUS_CATEGORY[status]) {
      category = STATUS_CATEGORY[status];
      severity = STATUS_SEVERITY[status] || severity;
      matchedRule = `status:${status}`;
    } else if (status >= 400) {
      category = 'Warning';
      severity = STATUS_SEVERITY[status] || 'medium';
      matchedRule = `status:${status}`;
    } else {
      category = 'Request Processing';
      severity = 'info';
      confidence = 90;
      matchedRule = `status:${status}`;
    }
  } else {
    for (const rule of CATEGORY_RULES) {
      if (rule.regex.test(text)) {
        category = rule.category;
        severity = level === 'error' || level === 'crit' || level === 'emerg'
          ? (rule.severity === 'low' ? 'medium' : rule.severity)
          : rule.severity;
        confidence = rule.confidence;
        matchedRule = `category:${rule.category}`;
        break;
      }
    }
  }

  if (!category) {
    category = 'Unknown';
    confidence = 60;
    matchedRule = 'fallback:unknown';
  }

  if (status && STATUS_SEVERITY[status] && (status >= 400 || status === 429)) {
    severity = STATUS_SEVERITY[status];
  }

  return { category, severity, confidence, matchedRule, securityTypes, status };
}

module.exports = {
  classify,
  LEVEL_SEVERITY,
  STATUS_SEVERITY,
  STATUS_CATEGORY,
  SECURITY_PATTERNS,
  CATEGORY_RULES,
  CATEGORIES: [
    'Startup', 'Shutdown', 'Configuration', 'Worker Initialization', 'Backend Communication',
    'Warning', 'Error', 'Performance', 'Security', 'Request Processing', 'Resource Not Found',
    'Network', 'Service Instability', 'Unknown',
  ],
  SEVERITIES: ['critical', 'high', 'medium', 'low', 'info'],
};
