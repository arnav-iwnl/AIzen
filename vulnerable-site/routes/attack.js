/**
 * Attack Page Renderer
 * Renders informative pages when attacks are detected
 */

function renderAttackPage(res, attackType, details) {
  const { param, payload, info } = details;
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>${attackType} Detected</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #fff8f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .alert { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .attack-type { color: #dc3545; font-size: 1.5rem; font-weight: bold; }
        .detail { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; }
        .info { background: #e7f3ff; border: 1px solid #b3d7ff; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }
        .btn:hover { background: #0056b3; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
      </style>
    </head>
    <body>
      <div style="max-width: 800px; margin: 0 auto; padding: 20px;">
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 4px; margin: 20px 0;">
          <h1 style="margin: 0 0 10px; color: #721c24;">🚨 ${attackType} Detected</h1>
          <p style="margin: 0;">The AIzen SIEM detected a potential ${attackType.toLowerCase()} attack.</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 4px; margin: 20px 0;">
          <h3>Attack Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><th style="text-align: left; padding: 8px;">Attack Type</th><td style="color: #dc3545; font-weight: bold;">${attackType}</td></tr>
            <tr><td style="padding: 8px;">Parameter</td><td><code>${param}</code></td></tr>
            <tr><td style="padding: 8px;">Payload</td><td><code>${payload}</code></td></tr>
          </table>
        </div>
        
        <div style="background: #e7f3ff; border: 1px solid #b3d7ff; padding: 15px; margin: 20px 0; border-radius: 4px;">
          <h3>What Happened?</h3>
          <p>${info}</p>
        </div>
        
        <div style="margin-top: 30px;">
          <a href="/" class="btn" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">← Back to Home</a>
        </div>
      </div>
    </body>
    </html>
  `;
  
  res.set('Content-Type', 'text/html');
  res.status(200).send(html);
}

module.exports = { renderAttackPage };