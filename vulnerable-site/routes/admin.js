/**
 * Main Admin Router - Mounts all admin sub-routes
 */
const express = require('express');
const router = express.Router();
const { renderAttackPage } = require('./attack');

// Mount sub-routes
router.use(require('./admin_config'));
router.use(require('./admin_users'));
router.use(require('./admin_logs'));

// Main admin dashboard
router.get('/api/admin', (req, res) => {
  res.redirect('/api/admin/dashboard');
});

// Dashboard page
router.get('/api/admin/dashboard', (req, res) => {
  // If no demo admin token is supplied, treat access as an exposure/attack and show feedback
  const token = req.headers['x-admin-token'] || req.query.token || null;
  if (!token) {
    return renderAttackPage(res, 'Unauthenticated Admin Access', { param: 'path', payload: req.path, info: 'Admin panel is exposed without authentication; anyone can access sensitive data.' });
  }
  // otherwise continue to show the dashboard (demo token not validated)
  res.set('Content-Type', 'text/html');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .vuln-banner { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px; border-radius: 4px; }
        .card { background: white; border: 1px solid #dee2e6; border-radius: 4px; margin: 10px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card-header { border-bottom: 1px solid #dee2e6; padding-bottom: 10px; margin-bottom: 15px; }
        .card-title { font-size: 1.25rem; font-weight: bold; color: #333; }
        .config-section { margin-bottom: 20px; }
        .config-key { font-weight: bold; color: #495057; }
        .config-value { font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        .sensitive { color: #dc3545; font-weight: bold; }
        .nav-tabs { display: flex; border-bottom: 1px solid #dee2e6; margin-bottom: 20px; }
        .nav-tab { padding: 10px 20px; cursor: pointer; border-bottom: 3px solid transparent; margin-bottom: -1px; }
        .nav-tab.active { border-bottom-color: #007bff; color: #007bff; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .btn { display: inline-block; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 5px; }
        .btn-danger { background: #dc3545; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; max-height: 400px; overflow-y: auto; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="vuln-banner">
          <strong>⚠️ CRITICAL: Unauthenticated Admin Panel Exposed!</strong>
          This admin panel has <strong>NO authentication or authorization</strong>. 
          Anyone with the URL can access sensitive configuration, user data, and system logs.
        </div>
        
        <div class="container">
          <h1>🔧 Admin Panel</h1>
          
          <div class="nav-tabs">
            <a href="/api/admin/dashboard" class="nav-tab active">Dashboard</a>
            <a href="/api/admin/config" class="nav-tab">Configuration</a>
            <a href="/api/admin/users" class="nav-tab">Users</a>
            <a href="/api/admin/logs" class="nav-tab">System Logs</a>
          </div>
          
          <div class="card">
            <div class="card-header"><span class="card-title">System Status</span></div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
              <div class="card">
                <div class="card-title">System Status</div>
                <div style="font-size: 1.5rem; color: #28a745; font-weight: bold;">● Online</div>
                <div style="font-size: 0.875rem; color: #6c757d;">Last restart: ${new Date().toISOString()}</div>
              </div>
              <div class="card">
                <div class="card-title">Uptime</div>
                <div style="font-size: 1.5rem; font-weight: bold;">${Math.floor(process.uptime() / 3600)}h ${Math.floor((process.uptime() % 3600) / 60)}m</div>
              </div>
              <div class="card">
                <div class="card-title">Memory Usage</div>
                <div style="font-size: 1.5rem; font-weight: bold;">${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB</div>
              </div>
              <div class="card">
                <div class="card-title">Node Version</div>
                <div style="font-size: 1.5rem; font-weight: bold;">${process.version}</div>
              </div>
            </div>
          </div>
          
          <div class="card">
            <div class="card-header"><span class="card-title">Quick Actions</span></div>
            <a href="/api/admin/config" class="btn btn-primary">View Configuration</a>
            <a href="/api/admin/users" class="btn btn-primary">Manage Users</a>
            <a href="/api/admin/logs" class="btn btn-primary">View Logs</a>
          </div>
        </div>
      </body>
      </html>
  `);
});

module.exports = router;