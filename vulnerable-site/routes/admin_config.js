/**
 * Admin Config Endpoint
 * GET /api/admin/config
 */
const express = require('express');
const router = express.Router();

const adminConfig = {
  database: {
    host: 'db.internal',
    port: 5432,
    name: 'aizen_prod',
    user: 'app_user',
    password: 'SuperSecretDBPass123!'
  },
  apiKeys: {
    stripe: 'sk_live_51H...secret_key...',
    aws: 'AKIA...access_key...',
    sendgrid: 'SG.xxxxxx...api_key...'
  },
  jwtSecret: 'super-secret-jwt-signing-key-do-not-share',
  encryptionKey: 'aes-256-gcm-encryption-key-32-bytes!!',
  featureFlags: {
    maintenanceMode: false,
    debugMode: true,
    experimentalFeatures: true
  }
};

router.get('/api/admin/config', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Config</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; padding: 20px; }
        .vuln-banner { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px; border-radius: 4px; }
        .card { background: white; border: 1px solid #dee2e6; border-radius: 4px; margin: 20px; padding: 20px; }
        .config-section { margin-bottom: 20px; }
        .config-key { font-weight: bold; color: #495057; }
        .config-value { font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        .sensitive { color: #dc3545; font-weight: bold; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
        a.back { display: inline-block; margin: 20px; color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="vuln-banner">
        <strong>⚠️ Sensitive Configuration Exposed!</strong> This page reveals all system configuration including database credentials, API keys, and secrets.
      </div>
      <a href="/api/admin" class="back">← Back to Admin</a>
      <div class="card">
        <h2>Database Configuration</h2>
        <pre>${JSON.stringify({...adminConfig.database, password: '********'}, null, 2)}</pre>
      </div>
      <div class="card">
        <h2>API Keys</h2>
        <pre>${JSON.stringify(adminConfig.apiKeys, null, 2)}</pre>
      </div>
      <div class="card">
        <h2>Secrets</h2>
        <pre>${JSON.stringify({ jwtSecret: adminConfig.jwtSecret, encryptionKey: adminConfig.encryptionKey }, null, 2)}</pre>
      </div>
      <div class="card">
        <h2>Feature Flags</h2>
        <pre>${JSON.stringify(adminConfig.featureFlags, null, 2)}</pre>
      </div>
      <a href="/api/admin" style="display: inline-block; margin: 20px; color: #007bff;">← Back to Admin</a>
    </body>
    </html>
  `);
});

module.exports = router;