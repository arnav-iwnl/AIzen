/**
 * Admin Users Endpoint
 * GET /api/admin/users
 */
const express = require('express');
const router = express.Router();

const adminUsers = [
  { id: 1, username: 'admin', email: 'admin@company.com', role: 'superadmin', lastLogin: '2026-09-01T10:00:00Z', active: true },
  { id: 2, username: 'ops', email: 'ops@company.com', role: 'admin', lastLogin: '2026-08-30T14:30:00Z', active: true },
  { id: 3, username: 'dev', email: 'dev@company.com', role: 'developer', lastLogin: '2026-09-01T09:15:00Z', active: true },
  { id: 4, username: 'test', email: 'test@company.com', role: 'viewer', lastLogin: '2026-08-28T16:45:00Z', active: false }
];

router.get('/api/admin/users', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Users</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; padding: 20px; }
        .vuln-banner { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-secondary { background: #e2e3e5; color: #383d41; }
        a.back { display: inline-block; margin: 20px; color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="vuln-banner">
        <strong>⚠️ User Data Exposed!</strong> All user accounts with roles and status visible without authentication.
      </div>
      <a href="/api/admin" style="display: inline-block; margin: 20px; color: #007bff;">← Back to Admin</a>
      <table>
        <thead>
          <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Last Login</th><th>Status</th></tr>
        </thead>
        <tbody>
          <tr><td>1</td><td>admin</td><td>admin@company.com</td><td>superadmin</td><td>2026-09-01T10:00:00Z</td><td><span class="badge badge-success">Active</span></td></tr>
          <tr><td>2</td><td>ops</td><td>ops@company.com</td><td>admin</td><td>2026-08-30T14:30:00Z</td><td><span class="badge badge-success">Active</span></td></tr>
          <tr><td>3</td><td>dev</td><td>dev@company.com</td><td>developer</td><td>2026-09-01T09:15:00Z</td><td><span class="badge badge-success">Active</span></td></tr>
          <tr><td>4</td><td>test</td><td>test@company.com</td><td>viewer</td><td>2026-08-28T16:45:00Z</td><td><span class="badge badge-danger">Inactive</span></td></tr>
        </tbody>
      </table>
      <br><a href="/api/admin" style="display: inline-block; margin: 20px; color: #007bff;">← Back to Admin</a>
    </body>
    </html>
  `);
});

module.exports = router;