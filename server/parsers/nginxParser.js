const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Nginx Combined Log Parser
 * Handles BOTH error.log and access.log formats.
 *
 * Error log format:
 *   2024/01/15 10:30:00 [error] 1234#0: *1 connect() failed (111: Connection refused)
 *   while connecting to upstream, client: 1.2.3.4, server: example.com
 *
 * Access log format (combined):
 *   25.92.32.150 - - [01/Jul/2026:14:58:44 +0000] "DELETE /api/products HTTP/1.1" 200 211
 *   "https://www.bing.com/" "curl/8.5.0"
 *
 * For access logs: extracts method, path, query, status, UA, referrer, IP
 * Runs attack heuristics (credential_probe, path_traversal, XSS, SQLi, scanner, brute_force)
 * For error logs: runs error-specific detection (upstream failures, SSL failures, config warnings)
 */
class NginxLogParser extends BaseParser {
  constructor() {
    super('nginx');

    // Error log regex
    // 2024/01/15 10:30:00 [error] 1234#0: *1 connect() failed...
    this.errorLineRegex = /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(?:\d+#\d+:)?\s*(?:\*\d+\s+)?(.+)$/;

    // Access log regex (combined format)
    // IP - - [timestamp] "request" status bytes "referrer" "UA"
    this.accessLineRegex = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?/;

    // Error patterns for categorization
    this.ERROR_PATTERNS = {
      upstreamFailure: /(?:upstream|connect\(\) failed|no live upstreams|upstream timed out|upstream connection)/i,
      sslHandshakeFailure: /(?:SSL_do_handshake.*failed|bad handshake|bad certificate|SSL routines.*error|handshake failure)/i,
      configWarning: /(?:conflicting server name|low address bits|meaningless|duplicate.*server|rewrite.*directive)/i,
      criticalError: /\[crit\]|\[emerg\]|\[alert\]/i,
      upstreamTimeout: /upstream timed out/i,
    };

    // Access log attack patterns (run on request line)
    this.ACCESS_ATTACK_PATTERNS = {
      credentialProbe: /(?:\/\.env|\.env\.|\/\.ssh\/|\/\.docker\/|\/config\.|\/credentials?\/|\/secret\/|\/kube\/|\/aws\/|\/\.aws\/|\/gcp\/|\/\.gcp\/|\/azure\/|\/\.azure\/|\/\.ssh\/|id_rsa|id_ecdsa|\.pem|\.key|\.bak|\.tmp|\/admin\/|\/\.git\/|\/\.svn\/|\/\.hg\/)/i,
      pathTraversal: /(?:\/etc\/passwd|\.\.\/|\.\.\\|\/proc\/|\/var\/log|\/etc\/shadow|\/etc\/group)/i,
      xssProbe: /(?:<script|javascript:|onerror\s*=|onload\s*=|<img\s+src|alert\s*\(|prompt\s*\(|eval\s*\()/i,
      sqlInjection: /(?:'\s*(?:OR|AND)\s+\d|UNION\s+SELECT|DROP\s+TABLE|--\s*$|%27|%22.*(?:OR|AND)|sleep\s*\(|benchmark\s*\()/i,
      scanner: /(?:acunetix|nikto|sqlmap|nmap|wvstest|dirbuster|wpscan|w3af|nessus|openvas|wfuzz|hydra|gobuster|dirb)/i,
      bruteForce: /(?:\/administrator\/|\/admin\/|\/wp-admin|\/wp-login|\/login\.php|\/signin|\/auth\/login).*(?:POST|401|403)/i,
    };
  }

  parseTimestamp(timestampStr) {
    // Error log: "2024/01/15 10:30:00" -> "2024-01-15T10:30:00"
    // Access log: "01/Jul/2026:14:58:44 +0000" -> ISO
    if (timestampStr.includes('/') && timestampStr.includes(':')) {
      if (timestampStr.includes('[')) {
        // Access log format: "01/Jul/2026:14:58:44 +0000"
        try {
          const parts = timestampStr.replace(':', ' ').split(' ');
          const dateStr = parts[0].replace(/\//g, ' ') + ' ' + parts[1] + ' ' + (parts[2] || '+0000');
          const date = new Date(dateStr);
          return isNaN(date.getTime()) ? null : date.toISOString();
        } catch {
          return null;
        }
      } else {
        // Error log format: "2024/01/15 10:30:00"
        const iso = timestampStr.replace(/\//g, '-').replace(' ', 'T');
        const date = new Date(iso);
        return isNaN(date.getTime()) ? null : date.toISOString();
      }
    }
    return null;
  }

  _extractErrorDetails(message) {
    const details = {};
    const clientMatch = message.match(/client:\s*(\S+)/);
    if (clientMatch) details.ip = clientMatch[1];
    const serverMatch = message.match(/server:\s*([^,\s]+)/);
    if (serverMatch) details.server = serverMatch[1];
    const upstreamMatch = message.match(/upstream:\s*"?([^",\s]+)"?/);
    if (upstreamMatch) details.upstream = upstreamMatch[1];
    return details;
  }

  _classifyError(message) {
    const signals = [];
    const lowerMsg = message.toLowerCase();

    if (this.ERROR_PATTERNS.criticalError.test(message)) {
      signals.push('NGINX_CRITICAL_ERROR');
    }
    if (this.ERROR_PATTERNS.upstreamFailure.test(message)) {
      signals.push('NGINX_UPSTREAM_FAILURE');
    }
    if (this.ERROR_PATTERNS.sslHandshakeFailure.test(message)) {
      signals.push('NGINX_SSL_HANDSHAKE_FAILURE');
    }
    if (this.ERROR_PATTERNS.configWarning.test(message)) {
      signals.push('NGINX_CONFIG_WARNING');
    }
    if (this.ERROR_PATTERNS.upstreamTimeout.test(message)) {
      signals.push('NGINX_UPSTREAM_TIMEOUT');
    }

    return signals;
  }

  _classifyAccess(requestLine) {
    const signals = [];
    if (this.ACCESS_ATTACK_PATTERNS.credentialProbe.test(requestLine)) {
      signals.push('CREDENTIAL_PROBE');
    }
    if (this.ACCESS_ATTACK_PATTERNS.pathTraversal.test(requestLine)) {
      signals.push('PATH_TRAVERSAL');
    }
    if (this.ACCESS_ATTACK_PATTERNS.xssProbe.test(requestLine)) {
      signals.push('XSS_PROBE');
    }
    if (this.ACCESS_ATTACK_PATTERNS.sqlInjection.test(requestLine)) {
      signals.push('SQL_INJECTION');
    }
    if (this.ACCESS_ATTACK_PATTERNS.scanner.test(requestLine)) {
      signals.push('SCANNER_SIGNATURE');
    }
    if (this.ACCESS_ATTACK_PATTERNS.bruteForce.test(requestLine)) {
      signals.push('ADMIN_BRUTE_FORCE');
    }
    return signals;
  }

  parseLine(line, lineNumber) {
    const trimmed = line.trim();
    if (!trimmed) return null;

    // Try error log format first
    let match = trimmed.match(this.errorLineRegex);
    if (match) {
      const [, timestampStr, level, message] = match;
      const timestamp = this.parseTimestamp(timestampStr);
      const errorSignals = this._classifyError(message);
      const errorDetails = this._extractErrorDetails(message);

      let category = 'Request Processing';
      let severity = 'info';
      let confidence = 80;

      if (errorSignals.length > 0) {
        category = 'Warning';
        severity = 'warning';
        confidence = 85;
      } else if (level === 'error' || level === 'crit' || level === 'emerg' || level === 'alert') {
        category = 'Error';
        severity = 'high';
        confidence = 90;
      } else if (level === 'warn' || level === 'warning') {
        category = 'Warning';
        severity = 'warning';
        confidence = 85;
      }

      const baseMessage = `nginx error: [${level}] ${message}`;
      const fingerprint = generateFingerprint(category, baseMessage);

      return {
        id: `log_${String(lineNumber).padStart(5, '0')}`,
        raw: trimmed,
        timestamp: timestamp,
        level: level.toLowerCase(),
        message: baseMessage,
        fingerprint,
        lineNumber,
        parsedAt: new Date().toISOString(),
        ip: null, // extracted via _extractErrorDetails if needed
        category,
        severity,
        confidence,
        securityTypes: errorSignals,
        source: 'nginx-error',
      };
    }

    // Try access log format
    const accessMatch = trimmed.match(this.accessLineRegex);
    if (accessMatch) {
      const [, ip, timestampStr, request, statusStr, size, referrer, userAgent] = accessMatch;
      const status = parseInt(statusStr, 10);

      let level = 'info';
      if (status >= 500) level = 'error';
      else if (status >= 400) level = 'warn';

      const timestamp = this.parseTimestamp(timestampStr);

      const reqParts = request.split(' ');
      const method = reqParts[0] || 'UNKNOWN';
      const url = reqParts[1] || '';
      const fullRequest = `${method} ${url}`;

      const accessSignals = this._classifyAccess(fullRequest);

      let category = 'Request Processing';
      let severity = 'info';
      let confidence = 80;
      const securityTypes = [];

      if (accessSignals.length > 0) {
        category = 'Security';
        severity = 'high';
        confidence = 92;
        securityTypes.push(...accessSignals);
      } else if (status >= 500) {
        category = 'Error';
        severity = 'high';
        securityTypes.push('SERVER_ERROR');
      } else if (status === 404) {
        category = 'Resource Not Found';
        severity = 'low';
        securityTypes.push('NOT_FOUND');
      } else if (status === 401 || status === 403) {
        category = 'Security';
        severity = 'medium';
        securityTypes.push('AUTH_FAILURE');
      } else if (status >= 400) {
        category = 'Warning';
        severity = 'medium';
      }

      const baseMessage = `nginx access: ${method} ${url} HTTP/1.1 ${status}`;
      const fingerprint = generateFingerprint(category, baseMessage);

      return {
        id: `log_${String(lineNumber).padStart(5, '0')}`,
        raw: trimmed,
        timestamp: this.parseTimestamp(timestampStr),
        level,
        message: `nginx access: ${method} ${url} HTTP/1.1 ${status}`,
        fingerprint,
        lineNumber,
        parsedAt: new Date().toISOString(),
        ip,
        category,
        severity,
        confidence,
        securityTypes: securityTypes.length > 0 ? securityTypes : (accessSignals.length > 0 ? accessSignals : undefined),
        source: 'nginx-access',
        status,
        method,
        url,
      };
    }

    // Fallback
    return {
      id: `log_${String(lineNumber).padStart(5, '0')}`,
      raw: trimmed,
      timestamp: null,
      level: 'unknown',
      message: trimmed,
      fingerprint: generateFingerprint('unknown', trimmed),
      lineNumber,
      parsedAt: new Date().toISOString(),
      category: 'Clean',
      severity: 'info',
      confidence: 60,
      source: 'nginx',
    };
  }

  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 10);
    if (lines.length === 0) return false;

    // Check both formats
    const errorMatches = lines.filter((line) => this.errorLineRegex.test(line)).length;
    const accessMatches = lines.filter((line) => this.accessLineRegex.test(line)).length;
    const total = errorMatches + accessMatches;
    return total / lines.length >= 0.5;
  }
}

module.exports = NginxLogParser;