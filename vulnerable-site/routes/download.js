/**
 * Download Endpoint - Path Traversal / Local File Inclusion (LFI)
 * 
 * GET /download?file=<payload>
 * 
 * Vulnerability: Path Traversal / Local File Inclusion
 * Attack example: /download?file=../../../etc/passwd
 * 
 * This simulates a vulnerable file download that doesn't validate
 * the file path, allowing directory traversal.
 */
// router already created above
const path = require('path');
const fs = require('fs');

// Simulated file system for demonstration
const simulatedFiles = {
  'etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User One:/home/user1:/bin/bash\nuser2:x:1001:1001:User Two:/home/user2:/bin/bash',
  'etc/shadow': 'root:$6$salt$hash:18000:0:99999:7:::\nuser1:$6$salt$hash:18000:0:99999:7:::\nuser2:$6$salt$hash:18000:0:99999:7:::',
  'var/log/auth.log': 'Sep  3 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.1\nSep  3 10:01:02 server sshd[1235]: Accepted password for user1 from 192.168.1.1',
  'etc/hosts': '127.0.0.1 localhost\n192.168.1.10 server.local',
  'var/www/html/index.html': '<html><body><h1>Welcome</h1></body></html>',
  'var/www/html/config.php': "<?php $db_pass = 'secret123'; $api_key = 'sk_live_abc123'; ?>",
  'home/user/.ssh/id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
};

/**
 * VULNERABLE: No proper path validation - allows directory traversal
 * This is intentionally vulnerable to path traversal
 */
function sanitizePath(userPath) {
  const normalized = path.normalize(userPath).replace(/^(\.\.[\/\\])+/, '');
  return userPath; // Intentionally NO sanitization
}

/**
 * Read file safely from simulated filesystem
 */
function readFileSafely(filePath) {
  const normalized = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
  const key = normalized.replace(/^[\/\\]+/, '');
  
  if (simulatedFiles[key]) {
    return { found: true, content: simulatedFiles[key] };
  }
  
  // Try with ../ prefix variations
  for (const key of Object.keys(simulatedFiles)) {
    if (filePath.includes(key.replace(/\//g, '\\'))) {
      return { found: true, content: simulatedFiles[key] };
    }
  }
  
  return { found: false, content: null };
}

const express = require('express');
const router = express.Router();

router.get('/download', (req, res) => {
  const file = req.query.file || '';
  
  if (!file) {
    return res.status(400).send(`
      <html>
        <body style="font-family: Arial; margin: 40px;">
          <h1>File Download</h1>
          <p>Please provide a file parameter: <code>/download?file=path/to/file</code></p>
          <hr>
          <h3>Example paths to try:</h3>
          <ul>
            <li><code>?file=../../../etc/passwd</code></li>
            <li><code>?file=../../../etc/shadow</code></li>
            <li><code>?file=../../../../var/log/auth.log</code></li>
            <li><code>?file=../../../../var/www/html/config.php</code></li>
            <li><code>?file=../../../home/user/.ssh/id_rsa</code></li>
          </ul>
        </body></html>
    `);
  }
  
  // VULNERABLE: No path validation - allows directory traversal
  const requestedPath = req.query.file;
  const result = readFileSafely(requestedPath);
  
  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>File Download</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; }
        .file-content { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow: auto; }
        .path-traversal { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; color: #721c24; }
      </style>
    </head>
    <body>
      <h1>File Download</h1>
      <div class="vuln-banner">
        <strong>⚠️ Vulnerable to Path Traversal</strong> - No path validation on file parameter.
      </div>
      
      <form method="GET" action="/download" style="margin-bottom: 20px;">
        <label>File path: </label>
        <input type="text" name="file" value="${req.query.file || ''}" placeholder="e.g., ../../../etc/passwd" style="width: 500px; padding: 8px;">
        <button type="submit">Download</button>
      </form>
      
      <hr>
      <strong>Requested file:</strong> <code>${req.query.file || ''}</code>
  `;
  
  if (req.query.file) {
    const result = readFileSafely(req.query.file);
    const payload = req.query.file || '';
    // If a traversal pattern is present, show the attack 404 feedback page
    if (/\.\.\//.test(payload) || /\.\.\\/.test(payload) || payload.includes('../') || payload.includes('..\\')) {
      if (result.found) {
        return require('./attack').renderAttackPage(res, 'Path Traversal / LFI', { param: 'file', payload, info: 'Requested file path appears to perform directory traversal and sensitive file contents were retrieved.' });
      } else {
        return require('./attack').renderAttackPage(res, 'Path Traversal Attempt', { param: 'file', payload, info: 'Requested file path appears to attempt directory traversal but file was not found in the simulated filesystem.' });
      }
    }

    if (result.found) {
      html += `
        <div class="path-traversal">
          <strong>🚨 PATH TRAVERSAL SUCCESSFUL!</strong><br>
          File contents retrieved via directory traversal.
        </div>
        <div class="file-content">${result.content}</div>
      `;
    } else {
      html += `
        <div style="color: #dc3545;">File not found: ${req.query.file}</div>
      `;
    }
  }
  
  const fullHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>File Download</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; }
        .file-content { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow: auto; }
        .path-traversal { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; color: #721c24; }
      </style>
    </head>
    <body>
      <h1>File Download</h1>
      <div class="vuln-banner">
        <strong>⚠️ Vulnerable to Path Traversal</strong> - No path validation on file parameter.
      </div>
      
      <form method="GET" action="/download" style="margin-bottom: 20px;">
        <label>File path: </label>
        <input type="text" name="file" value="${req.query.file || ''}" placeholder="e.g., ../../../etc/passwd" style="width: 500px; padding: 8px;">
        <button type="submit">Download</button>
      </form>
      
      <hr>
      <strong>Requested file:</strong> <code>${req.query.file || ''}</code>
      
      ${req.query.file ? (() => {
        const result = readFileSafely(req.query.file);
        if (result.found) {
          return `
            <div class="path-traversal">
              <strong>🚨 PATH TRAVERSAL SUCCESSFUL!</strong><br>
              File contents retrieved via directory traversal.
            </div>
            <div class="file-content">${result.content}</div>
          `;
        } else {
          return `<div style="color: #dc3545;">File not found: ${req.query.file}</div>`;
        }
      })() : ''}
      
      <hr>
      <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
  `;
  
  res.set('Content-Type', 'text/html');
  res.send(fullHtml);
});

module.exports = router;