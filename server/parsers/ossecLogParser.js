const BaseParser = require('./baseParser');
const { generateFingerprint } = require('../utils/helpers');

/**
 * OSSEC / Wazuh Alert Parser
 *
 * Block-based format (one alert per multi-line block):
 *     ** Alert <unixtime>: - group1,group2,...
 *     <ts> (<hostname>) <agent>-><location>
 *     Rule: <id> (level <lvl>) -> '<description>'
 *     Src IP: <ip>
 *     ...raw log body...
 *
 * parseLine buffers lines until the next "** Alert" header completes a block,
 * then emits one structured entry per alert (message = "<desc> <body>", the
 * exact shape the v2 classifier was trained on). flushPending() returns any
 * buffered tail block for streamed uploads.
 */
class OssecLogParser extends BaseParser {
  constructor() {
    super('ossec');
    this.ALERT = /^\*\* Alert (\S+): - (.*)$/;
    this.HEADER = /^(\d{4} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}) \(([^)]+)\) (.+?)-?>?(.+)$/;
    this.RULE = /^Rule:\s*(\d+)\s*\(level\s*(\d+)\)\s*->\s*'([^']*)'/;
    this.SRCIP = /^Src IP:\s*(\S+)/;
    this.DSTIP = /^Dst IP:\s*(\S+)/;
    this.runner = 0;
    this._block = null;
  }

  reset() {
    this._block = null;
    this.runner = 0;
  }

  _newBlock() {
    return {
      ts: null, groups: [], rule_id: null, level: null, desc: '',
      host: null, src_ip: null, dst_ip: null, body: [], rawLines: [],
    };
  }

  _levelTo(level) {
    // OSSEC rule level -> server severity vocabulary (crit/error/warn/info)
    if (level >= 10) return 'crit';
    if (level >= 7) return 'error';
    if (level >= 4) return 'warning';
    return 'info';
  }

  _parseTs(header) {
    // "2026 Sep 09 00:00:40" -> Date (local) -> ISO
    const m = header.match(/^(\d{4}) ([A-Z][a-z]{2}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})$/);
    if (!m) return null;
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
                     Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const d = new Date(+m[1], months[m[2]], +m[3], +m[4], +m[5], +m[6]);
    return isNaN(d.getTime()) ? null : d.toISOString();
  }

  _emit(rawHeaderLine) {
    const b = this._block;
    if (!b || !b.rule_id) return null;
    let body = b.body.join(' ').trim();
    if (body.length > 512) body = body.slice(0, 512);
    let message = b.desc;
    if (body) message = `${b.desc} ${body}`.trim();
    if (message.length > 512) message = message.slice(0, 512);
    if (!message) return null;

    const level = this._levelTo(b.level);
    return {
      id: `ossec_${String(this.runner++).padStart(5, '0')}`,
      raw: b.rawLines.join('\n'),
      timestamp: b.ts,
      level,
      message,
      fingerprint: generateFingerprint(level, message),
      lineNumber: b._firstLine,
      parsedAt: new Date().toISOString(),
      src_ip: b.src_ip,
      dst_ip: b.dst_ip,
      host: b.host,
      groups: b.groups,
      rule_id: b.rule_id,
      rule_level: b.level,
    };
  }

  /**
   * Buffer one line; returns a completed alert entry only when a new
   * "** Alert" header closes the previous block.
   */
  parseLine(line, lineNumber) {
    const trimmed = line.trim();
    if (!trimmed) return null;

    const header = this.ALERT.exec(trimmed);
    if (header) {
      const finished = this._emit();
      this._block = this._newBlock();
      this._block.ts = this._parseTs(header[1]);
      // first non-empty date line in the body carries the real timestamp
      this._block.groups = header[2].split(',').map((g) => g.trim()).filter(Boolean);
      this._block._firstLine = lineNumber;
      return finished;
    }

    if (!this._block) {
      this._block = this._newBlock();
      this._block._firstLine = lineNumber;
    }

    const rule = this.RULE.exec(trimmed);
    if (rule) {
      this._block.rule_id = rule[1];
      this._block.level = parseInt(rule[2], 10);
      this._block.desc = rule[3];
      return null;
    }
    const head = this.HEADER.exec(trimmed);
    if (head && !this._block.ts) {
      this._block.ts = this._parseTs(head[1]);
      this._block.host = head[2];
      return null;
    }
    const src = this.SRCIP.exec(trimmed);
    if (src) { this._block.src_ip = src[1]; return null; }
    const dst = this.DSTIP.exec(trimmed);
    if (dst) { this._block.dst_ip = dst[1]; return null; }

    this._block.body.push(trimmed);
    this._block.rawLines.push(line.replace(/\r$/, ''));
    return null;
  }

  /**
   * Return the tail block if a streamed upload ended without a closing
   * "** Alert" header. Called by preprocessor after the read loop.
   */
  flushPending() {
    const finished = this._emit();
    this._block = null;
    return finished;
  }

  canParse(sampleContent) {
    const lines = sampleContent.split(/\r?\n/).filter((l) => l.trim()).slice(0, 10);
    return lines.some((l) => /^\*\* Alert \d+/.test(l.trim()));
  }
}

module.exports = OssecLogParser;