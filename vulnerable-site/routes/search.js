/**
 * Search Endpoint - Reflected XSS via search query
 * 
 * GET /search?q=<payload>
 * 
 * Vulnerability: Reflected XSS - user input directly reflected in response without sanitization
 * Attack example: /search?q=<script>alert('XSS')</script>
 */
const express = require('express');
const router = express.Router();
const { renderAttackPage } = require('./attack');

router.get('/search', (req, res) => {
  const query = req.query.q || '';
  const searchTerm = query.trim();
  
  // Simulate search results with reflected user input (XSS vulnerable)
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Search Results</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .search-box { margin-bottom: 20px; }
        .result { background: #f5f5f5; padding: 10px; margin: 10px 0; }
      </style>
    </head>
    <body>
      <h1>Search Results</h1>
      <div class="search-box">
        <form method="GET" action="/search">
          <input type="text" name="q" value="${searchTerm}" placeholder="Search..." size="50">
          <button type="submit">Search</button>
        </form>
      </div>
      <div class="results">
        <h2>Results for: ${searchTerm}</h2>
        <div class="result">
          <strong>Found 3 results for "${searchTerm}"</strong>
        </div>
        <div class="result">
          <a href="#">Result 1 matching "${searchTerm}"</a>
        </div>
        <div class="result">
          <a href="#">Result 2 matching "${searchTerm}"</a>
        </div>
        <div class="result">
          <a href="#">Result 3 matching "${searchTerm}"</a>
        </div>
      </div>
      <hr>
      <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
  `;
  
  // Detect obvious XSS payloads and present an attack feedback page
  const lower = searchTerm.toLowerCase();
  if (/[<>]|<script|onerror|javascript:/i.test(searchTerm) || lower.includes('<script')) {
    return renderAttackPage(res, 'Reflected XSS (search)', { param: 'q', payload: searchTerm, info: 'User input was reflected back into the HTML without sanitization.' });
  }

  res.set('Content-Type', 'text/html');
  res.send(html);
});

module.exports = router;