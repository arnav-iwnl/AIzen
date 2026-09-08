/**
 * Telegram notification service — rate-limited alerts for security breaches.
 *
 * Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHANNEL_ID in server/.env to enable.
 * When disabled, every call is a silent no-op so the rest of the pipeline
 * is never affected.
 */
const https = require('https');
const config = require('../config/app.config');
const logger = require('../utils/logger');

const COOLDOWN_MS = 5000; // min gap between Telegram messages
let lastSentAt = 0;

function isEnabled() {
  return !!(config.telegram && config.telegram.botToken && config.telegram.channelId);
}

/**
 * Send a security-alert message to the configured Telegram channel.
 * Coalesces rapid-fire attacks (max 1 message per COOLDOWN_MS).
 * @param {Object} event - the realtime event object
 */
function notify(event) {
  if (!isEnabled()) return;
  const now = Date.now();
  if (now - lastSentAt < COOLDOWN_MS) return;
  lastSentAt = now;

  const ts = new Date(event.ts);
  const hh = String(ts.getUTCHours()).padStart(2, '0');
  const mm = String(ts.getUTCMinutes()).padStart(2, '0');
  const dd = String(ts.getUTCDate()).padStart(2, '0');
  const mo = String(ts.getUTCMonth() + 1).padStart(2, '0');
  const yy = String(ts.getUTCFullYear()).slice(-2);
  const timeStr = `${hh}:${mm} ${dd}/${mo}/${yy}`;

  const threatLevel = event.level === 'error' || event.level === 'crit' || event.level === 'critical' ? 'Error' : 'Warn';
  const types = (event.securityTypes || []).join(', ');
  const ip = event.ip || 'unknown';
  const content = (event.raw || event.message || '').slice(0, 200);

  const text =
    `⚠️ *Security Alert*\n` +
    `*Threat:* ${threatLevel}\n` +
    `*Type:* ${types}\n` +
    `*Confidence:* ${event.confidence}%\n` +
    `*Time:* ${timeStr}\n` +
    `*IP Address:* ${ip}\n` +
    `*Content:* \`${content}\``;

  const payload = JSON.stringify({
    chat_id: config.telegram.channelId,
    text,
    parse_mode: 'Markdown',
  });

  const options = {
    hostname: 'api.telegram.org',
    port: 443,
    path: `/bot${config.telegram.botToken}/sendMessage`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
  };

  const req = https.request(options, (res) => {
    let body = '';
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      if (res.statusCode !== 200) {
        logger.warn(`[telegram] API ${res.statusCode}: ${body.slice(0, 200)}`);
      }
    });
  });

  req.on('error', (err) => {
    logger.warn(`[telegram] send failed: ${err.message}`);
  });

  req.write(payload);
  req.end();
}

module.exports = { notify, isEnabled };
