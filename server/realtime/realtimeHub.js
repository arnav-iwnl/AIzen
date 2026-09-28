const parserFactory = require('../parsers/parserFactory');
const rules = require('../rules/logRules');
const config = require('../config/app.config');
const logger = require('../utils/logger');
const v2Bridge = require('../ml/v2Bridge');
const telegram = require('../services/telegramService');
const { techniquesFor, mitreUrl } = require('../mitre/attackMap');

/**
 * RealtimeHub — in-memory real-time SIEM feed (SSE).
 *
 * Isolated from the analysis LogStore: live traffic lives in its own ring
 * buffer with running counters. Every ingested line is parsed + classified
 * synchronously (µs) and pushed to all connected SSE clients.
 */
class RealtimeHub {
  constructor() {
    this.clients = new Set();
    this.events = [];
    this.alerts = [];
    this.nextId = 1;
    this.since = new Date().toISOString();

    this.counters = {
      total: 0,
      errors: 0,
      warnings: 0,
      security: 0,
      ratePerSec: 0,
      categoryCounts: {},
      since: this.since,
    };

    // Rolling window bookkeeping
    this.windowTicks = [];       // { ts, kind: 'error'|'warn'|'security' }
    this.rateTicks = [];         // timestamps of recent events (10s)
    this.lastErrorAlertAt = 0;
    this.lastSecurityAlertAt = 0;
  }

  // ── Ingestion pipeline ─────────────────────────────────────────────────────
  /**
   * Parse + classify a raw line and broadcast it.
   *
   * v2 PRIMARY: when the deep model is enabled it runs on EVERY line and its
   * attack verdict is merged with the deterministic rules BEFORE the event is
   * published — a line v2 flags shows as Security/high immediately (no
   * fire-and-forget, no post-hoc alert). When v2 is disabled this is exactly
   * the legacy synchronous path.
   * @param {string} raw - one log line
   * @param {string} source - e.g. demo action id, 'manual'
   * @param {Object|null} preV2 - pre-computed v2 result (skips ONNX inference)
   * @param {string[]} [expectedTechniques] - ATT&CK ids the SOURCE says this
   *   request exercises (e.g. the vulnerable site declaring which attack its
   *   route models). Kept separate from `techniques`: it is ground truth for
   *   checking the detector, never an input to it.
   * @returns {Promise<Object|null>} the published event (null if line was blank)
   */
  async ingestLine(raw, source = 'manual', preV2 = null, expectedTechniques = null) {
    const trimmed = (raw || '').trim();
    if (!trimmed) return null;

    let parsed;
    try {
      const parser = parserFactory.getParser(trimmed);
      parsed = parser.parseLine(trimmed, 0);
      if (parsed) parsed.format = parser.formatName; // parsers don't set .format on entries
    } catch (err) {
      parsed = null;
    }

    const entry = parsed || {
      level: 'unknown',
      message: trimmed,
      format: 'generic',
    };

    const cls = rules.classify({ message: entry.message, level: entry.level, raw: trimmed });

    const event = {
      id: this.nextId++,
      ts: new Date().toISOString(),
      raw: trimmed,
      format: entry.format || 'generic',
      level: entry.level,
      message: entry.message || trimmed,
      category: cls.category,
      severity: cls.severity,
      confidence: cls.confidence,
      securityTypes: cls.securityTypes,
      source,
      ip: entry.ip || null,
    };

    // Map classification severity to an event-level when it indicates a
    // more serious condition than the parser-derived `entry.level`.
    // This makes Security/high (or other high severities) surface as errors
    // in the realtime feed even when the parser guessed `info`.
    const severityToLevel = {
      critical: 'critical',
      high: 'error',
      medium: 'warn',
      low: 'notice',
      info: 'info',
    };

    const levelPriority = {
      debug: 0, info: 1, notice: 2, warn: 3, warning: 3, error: 4, err: 4,
      crit: 5, critical: 5, alert: 6, emerg: 7,
    };

    const parsedLevel = (entry.level || 'info').toLowerCase();
    const mapped = severityToLevel[(cls.severity || '').toLowerCase()];
    if (mapped) {
      const currentPr = levelPriority[parsedLevel] || 1;
      const mappedPr = levelPriority[mapped] || 1;
      if (mappedPr > currentPr) {
        event.level = mapped;
      }
    }

    if (v2Bridge.isEnabled()) {
      const v2 = preV2 || await v2Bridge.classifyLine(trimmed);
      if (v2 && v2.is_attack) {
        event.v2Attack = v2.attack_type;
        event.v2Confidence = v2.attack_confidence;
        event.securityTypes = Array.from(new Set([...event.securityTypes, v2.attack_type]));

        // v2 is a SECOND OPINION, not the primary detector: it may add its
        // attack_type (and its technique) to a line, but it may not on its own
        // turn a line the rules called clean into Security. With the current
        // calibration (per-class thresholds sit at ~0.05 because the holdout is
        // in-distribution) an unconstrained v2 flagged a plain `GET /about 200`
        // as credential_probe, i.e. it fired on almost anything it had an
        // opinion about. A v2-alone escalation now needs a genuinely high
        // confidence; tune with V2_SOLO_MIN_CONFIDENCE.
        const soloBar = config.v2.soloMinConfidence;
        const rulesAlreadyFlagged = cls.securityTypes.length > 0;
        if (rulesAlreadyFlagged || v2.attack_confidence >= soloBar) {
          event.category = 'Security';
          event.severity = 'high';
          event.level = 'error';
          // Never downgrade the rule engine's verdict with a weaker v2 opinion.
          // This line was assigned confidence 92 by the rules; overwriting it
          // with v2's 44% reported the less certain detector's number as the
          // alert's confidence. Take the stronger of the two.
          event.confidence = Math.max(cls.confidence || 0, Math.round(v2.attack_confidence * 100));
        } else {
          // Keep the verdict as a non-escalating signal so the UI can still
          // surface it without it becoming an alert.
          event.v2Only = true;
        }
      }
    }

    // MITRE ATT&CK mapping. Done AFTER the v2 merge so the technique set covers
    // both detectors: securityTypes now holds the rule families plus the deep
    // model's attack_type, and attackMap.famKey normalizes both spellings into
    // one family space. Attached here (the single event literal) so the ring
    // buffer, all three SSE frame types, the snapshot and Telegram all carry it.
    // Compact on purpose — this object is replicated per event and buffered 250x.
    //
    // Attribution follows the PRIMARY detector: when the rules matched security
    // families, those decide the technique and v2 only fills in when the rules
    // were silent. Without this, v2 calling a SQL-injection payload
    // "bruteforce" added a bogus T1110 alongside the correct T1190.
    const primaryTypes = cls.securityTypes.length > 0
      ? cls.securityTypes
      : (event.v2Attack ? [event.v2Attack] : []);
    const techs = techniquesFor(primaryTypes);
    if (techs.length) {
      // mitreUrl() must be applied here: attackMap's id-indexed catalog entries
      // carry no url of their own (the RCA path adds it when it builds its
      // payload), so emitting the entry verbatim shipped undefined urls.
      event.techniques = techs.map((t) => ({ id: t.id, name: t.name, tactic: t.tactic, url: mitreUrl(t.id) }));
    }
    if (Array.isArray(expectedTechniques) && expectedTechniques.length) {
      event.expectedTechniques = expectedTechniques;
    }

    // Notify (bell + Telegram) for any Security or Error-level event, not just
    // v2-flagged attacks — rules-detected threats and app errors alert too.
    const shouldNotify =
      event.category === 'Security' ||
      ['error', 'crit', 'critical', 'emerg', 'alert'].includes(event.level);
    if (shouldNotify) {
      this.publish({ type: 'attack', event });
      logger.info('[realtime] notify', { category: event.category, level: event.level, v2Attack: event.v2Attack, ip: event.ip, telegramEnabled: telegram.isEnabled() });
      telegram.notify(event);
    }

    this._record(event);
    this.publish({ type: 'log', event });
    this._maybeAlert(event);
    return event;
  }

  _record(event) {
    this.events.push(event);
    if (this.events.length > config.realtime.bufferSize) this.events.shift();

    const c = this.counters;
    c.total++;
    if (['error', 'crit', 'critical', 'emerg', 'alert'].includes(event.level)) c.errors++;
    if (['warn', 'warning'].includes(event.level)) c.warnings++;
    if (event.securityTypes.length > 0) c.security++;
    c.categoryCounts[event.category] = (c.categoryCounts[event.category] || 0) + 1;

    // Rolling rate (10s)
    this.rateTicks.push(Date.now());
    const cutoff = Date.now() - 10000;
    while (this.rateTicks.length && this.rateTicks[0] < cutoff) this.rateTicks.shift();
    c.ratePerSec = Math.round((this.rateTicks.length / 10) * 10) / 10;

    // Rolling window for alerts (60s)
    const kind = event.securityTypes.length > 0 ? 'security' : event.level === 'error' || event.level === 'crit' ? 'error' : event.level === 'warn' ? 'warn' : null;
    if (kind) {
      this.windowTicks.push({ ts: Date.now(), kind });
      const wCutoff = Date.now() - config.realtime.windowSeconds * 1000;
      while (this.windowTicks.length && this.windowTicks[0].ts < wCutoff) this.windowTicks.shift();
    }
  }

  _maybeAlert(event) {
    const now = Date.now();
    const windowMs = config.realtime.windowSeconds * 1000;
    const counts = { error: 0, security: 0, warn: 0 };
    for (const t of this.windowTicks) counts[t.kind]++;

    if (counts.error >= config.realtime.errorAlertThreshold && now - this.lastErrorAlertAt > windowMs) {
      this.lastErrorAlertAt = now;
      const severity = counts.error >= config.realtime.errorAlertThreshold * 2 ? 'critical' : 'high';
      this._pushAlert({
        severity,
        metric: 'error-rate',
        window: `${config.realtime.windowSeconds}s`,
        title: `${counts.error} errors in the last ${config.realtime.windowSeconds}s`,
        detail: `Error rate crossed the ${config.realtime.errorAlertThreshold}-per-${config.realtime.windowSeconds}s threshold. Latest: ${event.message.slice(0, 120)}`,
      });
    }

    if (counts.security >= config.realtime.securityAlertThreshold && now - this.lastSecurityAlertAt > windowMs) {
      this.lastSecurityAlertAt = now;
      this._pushAlert({
        severity: 'critical',
        metric: 'security-events',
        window: `${config.realtime.windowSeconds}s`,
        title: `${counts.security} security events in the last ${config.realtime.windowSeconds}s`,
        detail: `Security signal rate crossed the ${config.realtime.securityAlertThreshold}-per-${config.realtime.windowSeconds}s threshold. Signals: ${event.securityTypes.join(', ')}.`,
      });
    }
  }

  _pushAlert(alert) {
    const full = { id: `alert-${this.nextId++}`, ts: new Date().toISOString(), ...alert };
    this.alerts.push(full);
    if (this.alerts.length > 20) this.alerts.shift();
    this.publish({ type: 'alert', alert: full });
    logger.warn(`[realtime] ALERT ${full.severity}: ${full.title}`);
  }

  // ── SSE client management ─────────────────────────────────────────────────
  subscribe(req, res) {
    // Dynamically set SSE CORS headers to match allowed origins
    const allowedOrigins = [config.frontendUrl, config.vulnerableSiteUrl].filter(Boolean);
    if (config.nodeEnv !== 'production') {
      allowedOrigins.push('http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:3000', 'http://127.0.0.1:3000');
    }

    const origin = req.get('origin');
    if (origin && !allowedOrigins.includes(origin)) {
      // Reject connections from disallowed origins
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('CORS origin not allowed');
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
      'Access-Control-Allow-Origin': origin || allowedOrigins[0] || '*',
      'Vary': 'Origin',
    });
    res.write(': connected\n\n');
    res.write(`data: ${JSON.stringify({ type: 'snapshot', ...this.getSnapshot() })}\n\n`);

    this.clients.add(res);

    const heartbeat = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(heartbeat);
        this.clients.delete(res);
      }
    }, config.realtime.heartbeatMs);

    req.on('close', () => {
      clearInterval(heartbeat);
      this.clients.delete(res);
    });
  }

  publish(payload) {
    const data = `data: ${JSON.stringify(payload)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(data);
      } catch {
        this.clients.delete(client);
      }
    }
  }

  getSnapshot() {
    return {
      events: [...this.events],
      alerts: [...this.alerts],
      counters: { ...this.counters, categoryCounts: { ...this.counters.categoryCounts } },
    };
  }

  clear() {
    this.events = [];
    this.alerts = [];
    this.nextId = 1;
    this.windowTicks = [];
    this.rateTicks = [];
    this.lastErrorAlertAt = 0;
    this.lastSecurityAlertAt = 0;
    this.since = new Date().toISOString();
    this.counters = {
      total: 0, errors: 0, warnings: 0, security: 0, ratePerSec: 0,
      categoryCounts: {}, since: this.since,
    };
    logger.info('[realtime] feed cleared');
  }
}

module.exports = new RealtimeHub();
