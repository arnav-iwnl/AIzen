const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * Key-Value Group Parser
 * Handles logs where each record is represented as four successive lines:
 * Time\nLevel\nCategory\nLog\n
 */
class KeyValueGroupParser extends BaseParser {
  constructor() {
    super('kv-group');
  }

  canParse(sampleContent) {
    if (!sampleContent) return false;
    const normalized = sampleContent.toLowerCase();
    // Detect header presence or repeated 'time' label
    const hasHeaders = /\btime\b/.test(normalized) && /\blevel\b/.test(normalized) && /\bcategory\b/.test(normalized) && /\blog\b/.test(normalized);
    if (hasHeaders) return true;

    // Also detect if many lines look like time entries (e.g. "1:58:02 AM") followed by level keywords
    const lines = sampleContent.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    let potentialGroups = 0;
    for (let i = 0; i + 3 < lines.length; i += 1) {
      const a = lines[i], b = lines[i + 1];
      if (/^\d{1,2}:\d{2}:\d{2}\s*(AM|PM)?/i.test(a) && /^(info|error|warn|unknown|debug|critical|notice)$/i.test(b)) {
        potentialGroups++;
      }
    }
    return potentialGroups > 0;
  }

  parseFile(content) {
    const lines = content.split(/\r?\n/).map((l) => l.trim());
    const parsed = [];
    const errors = [];
    let i = 0;
    let entryIdx = 1;

    while (i < lines.length) {
      // look for a 4-line group
      if (i + 3 < lines.length) {
        const t = lines[i], lvl = lines[i + 1], cat = lines[i + 2], log = lines[i + 3];
        if (t && lvl && cat && log) {
          // Heuristic: time-like, level-like
          if (/^\d{1,2}:\d{2}:\d{2}/.test(t) && lvl.trim().length <= 40) {
            let level = (lvl || 'unknown').toLowerCase();
            let message = log;
            try {
              // First try a focused regex for method followed by a path (e.g. "GET /index.html HTTP/1.1")
              let found = false;
              const rxPathExact = /(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\/[^")'\s]+)\s+HTTP\/[0-9.]+/gi;
              let exactMatches = Array.from(log.matchAll(rxPathExact));
              if (exactMatches.length > 0) {
                const m = exactMatches[exactMatches.length - 1];
                const method = m[1];
                const url = m[2];
                // try to find status after the match
                let status = null;
                if (typeof m.index === 'number') {
                  const look = log.slice(m.index + m[0].length, m.index + m[0].length + 40);
                  const sMatch = look.match(/\s(\d{3})\b/);
                  if (sMatch) status = parseInt(sMatch[1], 10);
                }
                message = `${method} ${url} - Status ${status || 'N/A'}`;
                if (status) {
                  if (status >= 500) level = 'error';
                  else if (status >= 400) level = 'warn';
                  else level = 'info';
                }
                found = true;
              }

              // Path-iter heuristic (fallback)
              const pathIter = Array.from(log.matchAll(/\/[^)"'\s]+/g)).map((m) => ({ path: m[0], index: m.index }));
              if (!found && pathIter.length > 0) {
                // Prefer a path that is followed by 'HTTP' (inner request), then file-like paths, then alphabetic paths
                let candidate = pathIter.find((p) => /HTTP\//i.test(log.slice(p.index, p.index + 60)));
                if (!candidate) {
                  const rev = [...pathIter].reverse();
                  candidate = rev.find((p) => /\.[a-z0-9]{1,6}\b/i.test(p.path));
                }
                if (!candidate) {
                  candidate = pathIter.find((p) => /^\/[A-Za-z]/.test(p.path) && !/[:\d]{2,}/.test(p.path));
                }
                if (!candidate) candidate = pathIter[pathIter.length - 1];
                const path = candidate.path;
                const pathIndex = candidate.index;
                if (pathIndex >= 0) {
                  // look back for a method within 60 chars
                  const lookBack = log.slice(Math.max(0, pathIndex - 60), pathIndex);
                  const methodMatch = lookBack.match(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\b/i);
                  const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
                  const lookForward = log.slice(pathIndex + path.length, pathIndex + path.length + 60);
                  const statusMatch = lookForward.match(/\b(\d{3})\b/);
                  const status = statusMatch ? parseInt(statusMatch[1], 10) : null;
                  message = `${method} ${path} - Status ${status || 'N/A'}`;
                  // adjust level based on status if present
                  if (status) {
                    if (status >= 500) level = 'error';
                    else if (status >= 400) level = 'warn';
                    else level = 'info';
                  }
                  found = true;
                }
              }

              if (!found) {
                // Try multiple regex forms: escaped quotes, plain quotes, and a loose match
                const rxEscaped = /\\\"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\\\"]+?)\s+HTTP\/[0-9.]+\\\"\s*(\d{3})?/gi;
                const rxPlain = /"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\"]+?)\s+HTTP\/[0-9.]+"\s*(\d{3})?/gi;
                const rxLoose = /(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s\"]+)\s+HTTP\/[0-9.]+/gi;
                // Prefer matches where the URL contains a path ("/...") to avoid picking IP tokens
                const rxPath = /(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\"\s]*\/[^"]+)\s+HTTP\/[0-9.]+/gi;
                let matches = Array.from(log.matchAll(rxPath));
                if (matches.length === 0) matches = Array.from(log.matchAll(rxEscaped));
                if (matches.length === 0) matches = Array.from(log.matchAll(rxPlain));
                if (matches.length === 0) matches = Array.from(log.matchAll(rxLoose));

                if (matches.length > 0) {
                  const m = matches[matches.length - 1];
                  const method = m[1];
                  const url = m[2];
                  let status = m[3] ? parseInt(m[3], 10) : null;

                  // If status not captured, try to find a 3-digit status shortly after the match
                  if (!status && typeof m.index === 'number') {
                    const look = log.slice(m.index + m[0].length, m.index + m[0].length + 40);
                    const sMatch = look.match(/\s(\d{3})\b/);
                    if (sMatch) status = parseInt(sMatch[1], 10);
                  }

                  // use status to adjust level if available
                  let effectiveLevel = level;
                  if (status) {
                    if (status >= 500) effectiveLevel = 'error';
                    else if (status >= 400) effectiveLevel = 'warn';
                    else effectiveLevel = 'info';
                  }
                  message = `${method} ${url} - Status ${status || 'N/A'}`;
                  level = effectiveLevel;
                }
              }
            } catch (e) {
              message = log;
            }
            const fingerprint = generateFingerprint(level, `${message}`);
            parsed.push({
              id: `log_${String(entryIdx).padStart(5, '0')}`,
              raw: `${t}\n${lvl}\n${cat}\n${log}`,
              timestamp: null,
              level,
              category: cat,
              message,
              fingerprint,
              lineNumber: i + 1,
              parsedAt: new Date().toISOString(),
            });
            entryIdx++;
            i += 4;
            continue;
          }
        }
      }

      // Fallback: treat single line as entry
      const single = lines[i];
      if (single) {
        const level = (/^(info|error|warn|unknown|debug|critical|notice)$/i.test(single) ? single.toLowerCase() : 'unknown');
        parsed.push({
          id: `log_${String(entryIdx).padStart(5, '0')}`,
          raw: single,
          timestamp: null,
          level,
          message: single,
          fingerprint: generateFingerprint(level, single),
          lineNumber: i + 1,
          parsedAt: new Date().toISOString(),
        });
        entryIdx++;
      }
      i += 1;
    }

    return { parsed, errors, totalLines: lines.length };
  }
}

module.exports = KeyValueGroupParser;
