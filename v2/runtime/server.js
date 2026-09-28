/**
 * server.js — minimal standalone HTTP wrapper around the v2 ONNX classifier.
 *
 * Uses Node's built-in http module (no Express dep) so the runtime stays lean
 * on the Render free tier. Enables deploying v2 as its OWN service to A/B it
 * against the legacy backend before wiring in-process (see ADOPTION.md).
 *
 *   POST /classify        { "message": "..." }
 *   POST /classify-batch  { "messages": ["...", ...] }
 *   GET  /health
 *
 * Run: node server.js   (default PORT=3000)
 */
const http = require('http');
const { V2Classifier } = require('./onnx_classifier');

const PORT = process.env.PORT || 3000;

let clf = null;

async function handle(req, res) {
  const url = (req.url || '').split('?')[0];
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  if (req.method === 'GET' && url === '/health') {
    if (!clf) return send(503, { status: 'model-not-loaded' });
    return send(200, { status: 'ok', attack_threshold: clf.threshold });
  }

  if ((req.method === 'POST') && (url === '/classify' || url === '/classify-batch')) {
    let body = '';
    for await (const chunk of req) body += chunk;
    let payload;
    try {
      payload = JSON.parse(body || '{}');
    } catch {
      return send(400, { error: 'invalid json' });
    }
    if (!clf) return send(503, { error: 'model-not-loaded' });

    try {
      if (url === '/classify') {
        if (!payload.message) return send(400, { error: 'message required' });
        return send(200, await clf.classifyLine(payload.message));
      }
      const messages = Array.isArray(payload.messages) ? payload.messages : [];
      if (!messages.length) return send(400, { error: 'messages required' });
      return send(200, { results: await clf.classifyBatch(messages) });
    } catch (e) {
      return send(500, { error: e.message });
    }
  }

  send(404, { error: 'not found' });
}

(async () => {
  try {
    clf = await V2Classifier.create();
    console.log(`[v2] model loaded (attack_threshold=${clf.threshold})`);
  } catch (e) {
    console.error(`[v2] startup: ${e.message}`);
    // keep serving /health with 503 until a model appears
  }
  http.createServer(handle).listen(PORT, () => {
    console.log(`[v2] listening on :${PORT}`);
  });
})();
