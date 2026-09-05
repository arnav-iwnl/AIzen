/**
 * Profile Endpoint - Reflected XSS via Profile Name
 * 
 * GET /profile?name=<payload>
 * 
 * Vulnerability: Reflected XSS - user input directly reflected in HTML response
 * Attack example: /profile?name=<img src=x onerror=alert('XSS')>
 */
const express = require('express');
const router = express.Router();
const { renderAttackPage } = require('./attack');

router.get('/profile', (req, res) => {
  const name = req.query.name || 'Guest';
  
  // VULNERABLE: Direct reflection of user input in HTML
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>User Profile</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; }
        .profile-card { border: 1px solid #dee2e6; border-radius: 4px; padding: 20px; max-width: 400px; }
        .xss-demo { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; color: #721c24; margin: 20px 0; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; }
      </style>
    </head>
    <body>
      <h1>User Profile</h1>
      <div class="vuln-banner">
        <strong>⚠️ Vulnerable to Reflected XSS</strong> - User input directly reflected in HTML response.
      </div>
      
      <form method="GET" action="/profile" style="margin-bottom: 20px;">
        <label>Name: </label>
        <input type="text" name="name" value="${name}" placeholder="Enter your name">
        <button type="submit">View Profile</button>
      </form>
      
      <div class="profile-card">
        <h2>Welcome, ${name}</h2>
        <p>This is your profile page.</p>
        <p>Your account was created on: ${new Date().toLocaleDateString()}</p>
        <p>Last login: ${new Date().toLocaleString()}</p>
      </div>
      
      <hr>
      <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
  `;
  
  // If input looks like an XSS payload, show the attack feedback page
  if (/[<>]|<script|onerror|javascript:/i.test(name)) {
    return renderAttackPage(res, 'Reflected XSS (profile)', { param: 'name', payload: name, info: 'Profile name is reflected directly into the page.' });
  }

  res.set('Content-Type', 'text/html');
  res.send(html);
});

module.exports = router;