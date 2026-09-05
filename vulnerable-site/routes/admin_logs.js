/**
 * Admin Logs Endpoint
 * GET /api/admin/logs
 */
const express = require('express');
const router = express.Router();

const systemLogs = [
  { timestamp: '2026-09-01T10:00:00Z', level: 'INFO', message: 'Application started', source: 'app' },
  { timestamp: '2026-09-01T10:01:23Z', level: 'WARN', message: 'High memory usage detected: 85%', source: 'monitor' },
  { timestamp: '2026-09-01T10:05:12Z', level: 'ERROR', message: 'Database connection pool exhausted', source: 'db' },
  { timestamp: '2026-09-01T10:10:45Z', level: 'INFO', message: 'Backup completed successfully', source: 'backup' },
  { timestamp: '2026-09-01T10:15:30Z', level: 'WARN', message: 'Failed login attempts from 192.168.1.100', source: 'auth' },
  { timestamp: '2026-09-01T10:20:00Z', level: 'INFO', message: 'New user registered: user3', source: 'auth' },
  { timestamp: '2026-09-01T10:30:00Z', level: 'WARN', message: 'Slow query detected: 2.3s', source: 'db' },
  { timestamp: '2026-09-01T10:35:00Z', level: 'INFO', message: 'Scheduled backup started', source: 'backup' },
];

router.get('/api/admin/logs', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>System Logs</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; padding: 20px; }
        .vuln-banner { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px; border-radius: 4px; }
        .log-entry { background: white; border: 1px solid #dee2e6; border-radius: 4px; margin: 10px; padding: 15px; }
        .log-header { display: flex; gap: 10px; margin-bottom: 5px; }
        .log-level { padding: 2px 8px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
        .log-error { background: #f8d7da; color: #721c24; }
        .log-warn { background: #fff3cd; color: #856404; }
        .log-info { background: #d4edda; color: #155724; }
        .log-source { font-size: 0.8rem; color: #6c757d; }
        .log-message { margin-top: 5px; }
        .log-timestamp { font-size: 0.8rem; color: #6c757d; }
        a.back { display: inline-block; margin: 20px; color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <div style="max-width: 900px; margin: 0 auto; padding: 20px;">
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px; border-radius: 4px;">
          <strong>⚠️ System Logs Exposed!</strong> All system logs including errors, warnings, and operational details visible without authentication.
        </div>
        <a href="/api/admin" style="display: inline-block; margin: 20px; color: #007bff;">← Back to Admin</a>
        <div style="max-width: 800px; margin: 0 auto;">
          ${systemLogs.map(log => `
            <div class="log-entry">
              <div class="log-header">
                <span class="log-level log-${log.level.toLowerCase()}">${log.level}</span>
                <span class="log-source">[${log.source}]</span>
                <span class="log-timestamp">${new Date(log.timestamp).toLocaleString()}</span>
              </div>
              <div class="log-message">${log.message}</div>
            </div>
          `).join('')}
        </div>
      </body>
      </html>
  `);
});

module.exports = router;