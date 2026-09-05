/**
 * Product Endpoint - SQL Injection via Product ID
 * 
 * GET /product?id=<payload>
 * 
 * Vulnerability: SQL Injection - user input directly concatenated into SQL query
 * Attack example: /product?id=1' OR '1'='1
 * 
 * This simulates a vulnerable product lookup that concatenates user input
 * directly into a SQL query without parameterization.
 */
const express = require('express');
const router = express.Router();

// Simulated product database
const products = {
  '1': { id: '1', name: 'Widget Pro', price: 29.99, description: 'Premium widget' },
  '2': { id: '2', name: 'Gadget Plus', price: 49.99, description: 'Advanced gadget' },
  '3': { id: '3', name: 'Tool Master', price: 19.99, description: 'Professional tool' },
};

function generateSQLQuery(id) {
  // VULNERABLE: Direct string concatenation (SQL injection)
  return `SELECT * FROM products WHERE id = '${id}'`;
}

function executeQuery(id) {
  // Simulate SQL injection by checking for injection patterns
  const lower = id.toLowerCase();
  
  // Check for classic SQLi patterns
  const isInjection = 
    lower.includes("' or '1'='1") ||
    lower.includes("' or '1'='1") ||
    lower.includes("union select") ||
    lower.includes("drop table") ||
    lower.includes("drop database") ||
    lower.includes("sleep(") ||
    lower.includes("benchmark(");
  
  if (isInjection) {
    // Simulate successful SQL injection - return all products
    return {
      injected: true,
      query: `SELECT * FROM products WHERE id = '${id}'`,
      message: 'SQL Injection successful! All products returned.',
      data: Object.values(products)
    };
  }
  
  // Normal query
  const match = id.match(/id\s*=\s*['"]?(\d+)['"]?/i);
  const idMatch = match ? match[1] : null;
  const product = products[idMatch];
  
  if (product) {
    return { injected: false, query: `SELECT * FROM products WHERE id = '${id}'`, data: [products[idMatch]] };
  }
  
  return { injected: false, query: `SELECT * FROM products WHERE id = '${id}'`, data: [], message: 'Product not found' };
}

router.get('/product', (req, res) => {
  const id = req.query.id || '';
  const rawQuery = `SELECT * FROM products WHERE id = '${id}'`;
  const result = executeQuery(id);
  
  // Build response
  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Product Details</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; }
        .query-box { background: #f8f9fa; padding: 15px; font-family: monospace; overflow-x: auto; }
        .product-card { border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin: 10px 0; }
        .sql-injection { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; color: #721c24; }
        code { background: #f8f9fa; padding: 2px 4px; }
      </style>
    </head>
    <body>
      <h1>Product Details</h1>
      <div class="vuln-banner">
        <strong>⚠️ Vulnerable to SQL Injection</strong> - This endpoint directly concatenates user input into SQL queries.
      </div>
      
      <form method="GET" action="/product" style="margin-bottom: 20px;">
        <label>Product ID: </label>
        <input type="text" name="id" value="${req.query.id || ''}" placeholder="Enter product ID (e.g., 1 or 1' OR '1'='1)">
        <button type="submit">Lookup</button>
      </form>
      
      <div class="query-box">
        <strong>SQL Query:</strong><br>
        <code>${req.query.id ? generateSQLQuery(req.query.id) : ''}</code>
      </div>
  `;
  
  if (result.injected) {
    // Render an informative 404 page explaining the SQL injection attempt
    return require('./attack').renderAttackPage(res, 'SQL Injection', { param: 'id', payload: req.query.id, info: result.message });
  }
  
  if (result.data && result.data.length > 0) {
    html += '<h3>Results:</h3>';
    result.data.forEach(product => {
      html += `
        <div class="product-card">
          <strong>ID:</strong> ${product.id}<br>
          <strong>Name:</strong> ${product.name}<br>
          <strong>Price:</strong> $${product.price}<br>
          <strong>Description:</strong> ${product.description}
        </div>
      `;
    });
  } else if (!result.injected) {
    html += '<p class="text-muted">No products found.</p>';
  }
  
  html += `
      <hr>
      <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
  `;
  
  res.set('Content-Type', 'text/html');
  res.send(html);
});

function generateSQLQuery(id) {
  return `SELECT * FROM products WHERE id = '${id}'`;
}

module.exports = router;