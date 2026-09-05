const fs = require('fs');
const path = require('path');
const parserFactory = require('../parsers/parserFactory');
const rules = require('../rules/logRules');
const realtimeHub = require('../realtime/realtimeHub');
const config = require('../config/app.config');
const logger = require('../utils/logger');

const DATA_DIR = path.resolve(__dirname, '../../data');
const DATA_FILES = ['access.log', 'test.log', 'acunetix.log', 'Apache_2k.log', 'synthetic_error.log'];

/**
 * Demo traffic generator.
 * Builds a payload pool from the real data/ files (per action), and emits
 * randomized live lines into the realtime hub.
 */
class DemoService {
  constructor() {
    this.pools = null;
    this.streamTimer = null;
    this.streamState = { running: false, rate: config.demo.defaultRatePerSecond, action: 'mixed', since: null };
    this.poolSize = config.demo.poolSize;

    this.ACTIONS = [
      { id: 'sqli', label: 'SQL Injection', category: 'Security', description: 'UNION / OR 1=1 / sleep probes against query params' },
      { id: 'xss', label: 'XSS Probe', category: 'Security', description: '<script>, onerror img, xsstag payloads in URLs' },
      { id: 'path-traversal', label: 'Path Traversal', category: 'Security', description: '../../../etc/passwd, %2e%2e%2f file reads' },
      { id: 'admin-bruteforce', label: 'Admin Brute Force', category: 'Security', description: 'POSTs to /administrator, /login, /wp-login' },
      { id: 'scanner', label: 'Vuln Scanner', category: 'Security', description: 'Acunetix / nikto-style automated probing' },
      { id: 'get-flood', label: 'GET Requests', category: 'Traffic', description: 'Normal GET request volume (200/3xx)' },
      { id: 'post-flood', label: 'POST Requests', category: 'Traffic', description: 'Normal POST submission volume' },
      { id: 'directory-forbidden', label: 'Directory Forbidden', category: 'Operational', description: 'Apache [client IP] Directory index forbidden errors' },
      { id: 'backend-error', label: 'Backend Error', category: 'Operational', description: 'mod_jk worker error states / child lookup failures' },
      { id: 'apache-startup', label: 'Apache Startup', category: 'Operational', description: 'workerEnv.init / jk2_init notice lines' },
      { id: 'mixed', label: 'Mixed Traffic', category: 'Traffic', description: 'Random blend of all traffic types' },
    ];
  }

  getActions() {
    return this.ACTIONS.map(({ id, label, category, description }) => ({ id, label, category, description }));
  }

  getStreamState() {
    return { ...this.streamState };
  }

  // ── Payload pool ──────────────────────────────────────────────────────────
  _ensurePool() {
    if (this.pools) return;
    const pools = {};
    const add = (key, raw, format) => {
      if (!pools[key]) pools[key] = [];
      if (pools[key].length < this.poolSize) pools[key].push({ raw, format });
    };

    for (const file of DATA_FILES) {
      const filePath = path.join(DATA_DIR, file);
      if (!fs.existsSync(filePath)) continue;
      let content, parser;
      try {
        content = fs.readFileSync(filePath, 'utf-8');
        parser = parserFactory.getParser(content);
      } catch {
        continue;
      }
      const { parsed } = parser.parseFile(content);

      const byFp = new Map();
      for (const log of parsed) {
        if (!byFp.has(log.fingerprint)) {
          byFp.set(log.fingerprint, { ...log, count: 1 });
        } else {
          byFp.get(log.fingerprint).count++;
        }
      }

      for (const p of byFp.values()) {
        const cls = rules.classify({ message: p.message, level: p.level, raw: p.raw });
        const types = cls.securityTypes;

        if (types.length) {
          if (types.includes('SQL_INJECTION')) add('sqli', p.raw, parser.formatName);
          if (types.includes('XSS_PROBE')) add('xss', p.raw, parser.formatName);
          if (types.includes('PATH_TRAVERSAL')) add('path-traversal', p.raw, parser.formatName);
          if (types.includes('ADMIN_BRUTE_FORCE') || types.includes('CREDENTIAL_PROBE')) add('admin-bruteforce', p.raw, parser.formatName);
          if (types.includes('SCANNER_SIGNATURE')) add('scanner', p.raw, parser.formatName);
          if (types.includes('DIRECTORY_FORBIDDEN')) add('directory-forbidden', p.raw, parser.formatName);
        } else if (p.level === 'error' || p.level === 'crit') {
          if (/mod_jk|jk2_init|workerEnv/i.test(p.message)) add('backend-error', p.raw, parser.formatName);
        } else if (p.level === 'notice' || p.level === 'info') {
          if (/^(POST|GET|PUT|DELETE|HEAD)/.test(p.message)) {
            if (/^POST/.test(p.message)) add('post-flood', p.raw, parser.formatName);
            else add('get-flood', p.raw, parser.formatName);
          } else if (/workerEnv\.init|jk2_init|Found child|scoreboard/i.test(p.message)) {
            add('apache-startup', p.raw, parser.formatName);
          }
        }
      }
    }

    this.pools = pools;
    logger.info(`[demo] payload pools ready: ${Object.entries(pools).map(([k, v]) => `${k}=${v.length}`).join(', ')}`);
  }

  // ── Line generation ───────────────────────────────────────────────────────
  _randomIP() {
    return `${rand(1, 255)}.${rand(0, 255)}.${rand(0, 255)}.${rand(0, 255)}`;
  }

  _nowAccess() {
    const d = new Date();
    const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
  }

  _nowApache() {
    const d = new Date();
    const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const p = (n) => String(n).padStart(2, '0');
    return `${DAYS[d.getUTCDay()]} ${MONTHS[d.getUTCMonth()]} ${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
  }

  _access(method, url, status, ua) {
    const ref = pick(['-', 'https://www.google.com/', 'https://www.bing.com/', 'http://192.168.4.161/DVWA']);
    return `${this._randomIP()} - - [${this._nowAccess()}] "${method} ${url} HTTP/1.1" ${status} ${rand(100, 5000)} "${ref}" "${ua}"`;
  }

  _error(level, msg) {
    return `[${this._nowApache()}] [${level}] ${msg}`;
  }

  _fallback(action) {
    const ua = pick(['Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/41.0.2228.0', 'curl/8.5.0', 'acunetix', 'Mozilla/5.0 (compatible; Googlebot/2.1)']);
    switch (action) {
      case 'sqli': return this._access('GET', pick(["/index.php?id=1' UNION SELECT username,password FROM users--", "/login?id=1' OR '1'='1", "/products?cat=1%20AND%20SLEEP(5)"]), pick([500, 200, 404]), ua);
      case 'xss': return this._access('GET', pick(['/search?q=<script>alert(1)</script>', "/profile?name=<img src=x onerror=alert(1)>", "/?q=%22%3E%3Cxsstag%3E()locxss%22"]), pick([200, 404]), ua);
      case 'path-traversal': return this._access('GET', pick(['/download?file=../../../etc/passwd', '/index.php?page=../../../../etc/shadow', "/static/%2e%2e%2f%2e%2e%2fwin.ini"]), pick([200, 404, 403]), ua);
      case 'admin-bruteforce': return this._access('POST', pick(['/administrator/index.php', '/wp-login.php', '/index.php/component/users/?task=user.login']), pick([303, 500, 401]), ua);
      case 'scanner': return this._access('GET', pick(['/wvtest', '/phpmyadmin/', '/.git/config', '/actuator/health']), pick([404, 403, 200]), 'acunetix');
      case 'get-flood': return this._access(pick(['GET', 'HEAD']), pick(['/', '/index.html', '/js/app.js', '/api/products', '/about']), pick([200, 301, 304]), ua);
      case 'post-flood': return this._access('POST', pick(['/api/products', '/index.php/component/search/', '/contact']), pick([200, 303, 500]), ua);
      case 'directory-forbidden': return this._error('error', `[client ${this._randomIP()}] Directory index forbidden by rule: /var/www/html/`);
      case 'backend-error': return this._error('error', `mod_jk child workerEnv in error state ${rand(6, 10)}`);
      case 'apache-startup': return pick([
        this._error('notice', 'workerEnv.init() ok /etc/httpd/conf/workers2.properties'),
        this._error('notice', `jk2_init() Found child ${rand(1000, 33000)} in scoreboard slot ${rand(6, 12)}`),
      ]);
      default: return this._access('GET', '/', 200, ua);
    }
  }

  _makeLine(action) {
    this._ensurePool();
    if (action === 'mixed') {
      // Realistic mix: interleave real attack payloads (from the data files)
      // with normal traffic so the deep model has something to catch live.
      const attackKeys = ['sqli', 'xss', 'path-traversal', 'scanner'];
      const avail = attackKeys.filter((k) => this.pools[k] && this.pools[k].length);
      if (avail.length && Math.random() < 0.55) {
        const key = pick(avail);
        const entry = pick(this.pools[key]);
        return this._randomize(entry.raw, entry.format);
      }
      return this._fallback(avail.length ? 'get-flood' : pick(attackKeys));
    }
    const pool = this.pools[action];
    if (pool && pool.length > 0) {
      const entry = pick(pool);
      return this._randomize(entry.raw, entry.format);
    }
    return this._fallback(action);
  }

  _randomize(raw, format) {
    return raw
      .replace(/\[[^\]]+\]/, () => (format === 'apache' ? `[${this._nowApache()}]` : `[${this._nowAccess()}]`))
      .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, () => this._randomIP());
  }

  // ── Public API ────────────────────────────────────────────────────────────
  async trigger(action, count = 1) {
    const safe = Math.min(Math.max(parseInt(count, 10) || 1, 1), config.demo.maxBurst);
    const target = this.ACTIONS.find((a) => a.id === action) ? action : 'mixed';

    let generated = 0;
    for (let i = 0; i < safe; i++) {
      try {
        const line = this._makeLine(target);
        if (await realtimeHub.ingestLine(line, target)) generated++;
      } catch (err) {
        logger.warn(`[demo] line failed for ${target}: ${err.message}`);
      }
    }
    logger.info(`[demo] triggered ${target} x${generated}`);
    return { action: target, requested: safe, generated };
  }

  startStream({ rate, action }) {
    this.stopStream();
    const safeRate = Math.min(Math.max(parseFloat(rate) || config.demo.defaultRatePerSecond, 0.5), 100);
    const safeAction = this.ACTIONS.find((a) => a.id === action) ? action : 'mixed';
    this.streamState = { running: true, rate: safeRate, action: safeAction, since: new Date().toISOString() };

    this.streamTimer = setInterval(() => {
      const act = this.streamState.action === 'mixed' ? pick(this.ACTIONS.map((a) => a.id)).id : this.streamState.action;
      try {
        const line = this._makeLine(act);
        realtimeHub.ingestLine(line, act).catch((err) => logger.warn(`[demo] stream line failed: ${err.message}`));
      } catch (err) {
        logger.warn(`[demo] stream line failed: ${err.message}`);
      }
    }, Math.round(1000 / safeRate));

    logger.info(`[demo] stream started: ${safeAction} @ ${safeRate}/s`);
    return this.getStreamState();
  }

  stopStream() {
    if (this.streamTimer) clearInterval(this.streamTimer);
    this.streamTimer = null;
    this.streamState = { ...this.streamState, running: false, since: null };
    return this.getStreamState();
  }
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

module.exports = new DemoService();
