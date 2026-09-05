/**
 * Login Endpoint - Brute Force Vulnerable Login
 * 
 * POST /login
 * GET /login (shows login form)
 * 
 * Vulnerabilities:
 * - No rate limiting / brute force protection
 * - No account lockout after failed attempts
 * - Weak password policy (no complexity requirements)
 * - User enumeration possible (different responses for valid/invalid users)
 * 
 * Attack example: Automated password spraying / credential stuffing
 */
const express = require('express');
const router = express.Router();

// In-memory user store (in production would be a database)
const users = {
  'admin': { password: 'admin123', role: 'admin', email: 'admin@example.com' },
  'user1': { password: 'password123', role: 'user', email: 'user1@example.com' },
  'user2': { password: 'password', role: 'user', email: 'user2@example.com' },
  'test': { password: 'test', role: 'user', email: 'test@example.com' },
  'demo': { password: 'demo', role: 'user', email: 'demo@example.com' },
};

// Track failed login attempts (in-memory, resets on restart)
const failedAttempts = new Map();

function getClientIP(req) {
  return req.ip || req.connection.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const attempts = failedAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  // Reset counter after 15 minutes
  if (now - attempts.lastAttempt > 15 * 60 * 1000) {
    attempts.count = 0;
  }
  
  return {
    allowed: attempts.count < 5, // Allow 5 attempts per 15 minutes
    remaining: Math.max(0, 5 - attempts.count),
    resetTime: attempts.lastAttempt + 15 * 60 * 1000
  };
}

function recordFailedAttempt(ip) {
  const attempts = failedAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  if (now - attempts.lastAttempt > 15 * 60 * 1000) {
    attempts.count = 0;
  }
  
  attempts.count++;
  attempts.lastAttempt = Date.now();
  failedAttempts.set(ip, attempts);
}

function recordSuccess(ip) {
  failedAttempts.delete(ip);
}

// GET /login - Show login form
router.get('/login', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .demo-creds { background: #e7f3ff; border: 1px solid #b3d7ff; padding: 15px; margin: 20px 0; border-radius: 4px; font-size: 14px; }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .brute-force-info { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; color: #721c24; margin: 20px 0; border-radius: 4px; }
        .footer-links { margin-top: 20px; text-align: center; }
        .footer-links a { color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <div style="max-width: 450px; margin: 40px auto;">
        <div class="container">
          <h1 style="text-align: center; margin-bottom: 10px;">Login</h1>
          <p style="text-align: center; color: #666;">Vulnerable Login Portal</p>
          
          <div class="vuln-banner">
            <strong>⚠️ Vulnerable to Brute Force Attacks</strong><br>
            No rate limiting, no account lockout, weak passwords allowed.
          </div>
          
          <div class="brute-force-info">
            <strong>🚨 Brute Force Vulnerable:</strong><br>
            - No rate limiting<br>
            - No account lockout<br>
            - No CAPTCHA<br>
            - User enumeration possible<br>
            <br>
            <strong>Demo Credentials:</strong><br>
            admin / admin123<br>
            user1 / password123<br>
            user2 / password<br>
            test / test<br>
            demo / demo
          </div>
          
          <form method="POST" action="/login">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" name="username" placeholder="Username" required autocomplete="username">
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
            </div>
            <button type="submit">Login</button>
          </form>
          
          <div class="demo-creds">
            <strong>Demo Accounts:</strong><br>
            admin / admin123 | user1 / password123 | user2 / password | test / test | demo / demo
          </div>
          
          <div class="footer-links">
            <a href="/">← Back to Home</a>
          </div>
        </div>
      </body>
    </html>
  `;
  
  res.set('Content-Type', 'text/html');
  res.send(html);
});

// POST /login - Process login
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Check rate limit
  const rateLimit = checkRateLimit(ip);
  
  if (!rateLimit.allowed) {
    return require('./attack').renderAttackPage(res, 'Brute Force / Rate Limit Triggered', { param: 'login', payload: req.ip, info: 'Multiple failed login attempts detected from this IP address.' });
  }
  
  if (!username || !password) {
    return res.status(400).send(`
      <html><body style="font-family: Arial; margin: 40px; text-align: center;">
        <h1 style="color: #dc3545;">Missing Credentials</h1>
        <p>Username and password are required.</p>
        <a href="/login">← Back to Login</a>
      </body></html>
    `);
  }
  
  const user = users[username];
  
  if (!user) {
    // User enumeration - different response for invalid user
    recordFailedAttempt(req.ip);
    return require('./attack').renderAttackPage(res, 'User Enumeration', { param: 'username', payload: username, info: 'Response reveals whether a username exists which enables user enumeration attacks.' });
  }
  
  if (user.password !== password) {
    // Wrong password
    recordFailedAttempt(req.ip);
    const rl = checkRateLimit(req.ip);
    return require('./attack').renderAttackPage(res, 'Invalid Password / Brute Force', { param: 'password', payload: '***hidden***', info: `Incorrect password for user "${username}". Remaining attempts: ${rl.remaining}` });
  }
  
  // Success!
  recordSuccess(req.ip);
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login Successful</title>
      <style>
        body { font-family: Arial; margin: 40px; text-align: center; }
        .success { color: #28a745; }
        .card { max-width: 400px; margin: 0 auto; padding: 30px; border: 1px solid #dee2e6; border-radius: 8px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1 class="success">✓ Login Successful</h1>
        <p>Welcome back, <strong>${username}</strong>!</p>
        <p>Role: ${users[username].role}</p>
        <p>Email: ${users[username].email}</p>
        <p style="color: #666; font-size: 14px;">IP: ${req.ip}</p>
        <hr>
        <a href="/" style="color: #007bff;">← Go to Home</a>
      </body>
      </html>
  `;
  
  res.set('Content-Type', 'text/html');
  res.send(html);
});

module.exports = router;