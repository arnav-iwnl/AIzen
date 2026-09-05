/**
 * Vulnerable Web Application for AIzen SIEM Demo
 * 
 * This is an intentionally vulnerable web application that simulates
 * common web vulnerabilities for security training and SIEM testing.
 * 
 * Endpoints:
 *   GET  /search?q=...        - Reflected XSS via search query
 *   GET  /product?id=...      - SQL Injection via product ID
 *   GET  /profile?name=...    - Reflected XSS via profile name
 *   GET  /download?file=...   - Path traversal / LFI
 *   POST /login               - Brute-forceable login (no rate limit)
 *   GET  /api/admin           - Unauthenticated admin endpoint
 * 
 * All requests are logged in Apache access log format and forwarded
 * to the AIzen SIEM backend for real-time breach detection.
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const logger = require('./middleware/logger');
const searchRoute = require('./routes/search');
const productRoute = require('./routes/product');
const profileRoute = require('./routes/profile');
const downloadRoute = require('./routes/download');
const loginRoute = require('./routes/login');
const adminRoute = require('./routes/admin');

const app = express();

// Load environment variables
require('dotenv').config();

const PORT = process.env.PORT || 5000;
const AIZEN_BACKEND_URL = process.env.AIZEN_BACKEND_URL || 'http://localhost:3000';
const AIZEN_FRONTEND_URL = process.env.AIZEN_FRONTEND_URL || 'http://localhost:5173';

// Middleware
app.use(cors({
  origin: [AIZEN_FRONTEND_URL, 'http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Add Referrer-Policy header to prevent referer leakage on page refresh
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logger middleware - logs every request and forwards to AIzen backend
app.use(require('./middleware/logger'));

// Parse body for all routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/', require('./routes/search'));
app.use('/', require('./routes/product'));
app.use('/', require('./routes/profile'));
app.use('/', require('./routes/download'));
app.use('/', require('./routes/login'));
app.use('/', require('./routes/admin'));

// Static files (landing page)
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'aizen-vulnerable-site', timestamp: new Date().toISOString() });
});

// 404 handler - show a friendly page that explains this demo app is intentionally vulnerable
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <title>Not Found</title>
      <style>body{font-family:Arial;margin:40px} .card{max-width:800px;background:#fff;padding:20px;border:1px solid #eee;border-radius:8px}</style>
    </head>
    <body>
      <div class="card">
        <h1>404 — Not Found</h1>
        <p>This demo application is intentionally vulnerable for training and SIEM testing. If you triggered an attack pattern, a dedicated feedback page will explain what was observed.</p>
        <p><a href="/">← Back to Home</a></p>
      </div>
    </body>
    </html>
  `);
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[Vulnerable Site] Error:', err);
  res.status(500).send('Internal Server Error');
});

app.listen(PORT, () => {
  console.log(`[Vulnerable Site] Running on http://localhost:${PORT}`);
  console.log(`[Vulnerable Site] Logs forwarded to: ${process.env.AIZEN_BACKEND_URL || 'http://localhost:3000'}`);
  console.log(`[Vulnerable Site] CORS enabled for: ${process.env.AIZEN_FRONTEND_URL || 'http://localhost:5173'}`);
});

module.exports = app;