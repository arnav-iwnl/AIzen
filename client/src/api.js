const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000/api';

/**
 * Upload a log file to the backend.
 * Gzips client-side (CompressionStream) so Render's CDN/WAF won't block the
 * body when the file contains attack payloads (e.g. ../../../etc/passwd).
 */
export async function uploadLogFile(file) {
  const stream = file.stream().pipeThrough(new CompressionStream('gzip'));
  const gzBlob = await new Response(stream).blob();
  const formData = new FormData();
  formData.append('logfile', gzBlob, `${file.name}.gz`);

  const res = await fetch(`${API_BASE}/logs/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: 'Upload failed' }));
    throw new Error(err.message || 'Upload failed');
  }
  return res.json();
}

/**
 * Check backend health status.
 */
export async function checkHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

/**
 * Get log store stats (after upload or preload).
 */
export async function getLogStats() {
  const res = await fetch(`${API_BASE}/logs/stats`);
  return res.json();
}

/**
 * Step 1: Classify logs.
 */
export async function classifyLogs(logs, model = null) {
  const body = {};
  if (logs && logs.length > 0) {
    body.logs = logs;
  }
  if (model) {
    body.model = model;
  }
  
  const res = await fetch(`${API_BASE}/ai/log-classification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Classification failed: ${text}`);
  }
  return res.json();
}

/**
 * Step 2: Generate incident timeline.
 */
export async function generateTimeline(options = {}) {
  const res = await fetch(`${API_BASE}/ai/incident-timeline`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      focus: options.focus || 'errors',
      maxEvents: options.maxEvents || 8,
      model: options.model,
    }),
  });
  if (!res.ok) throw new Error('Timeline generation failed');
  return res.json();
}

/**
 * Step 3: Root cause analysis.
 */
export async function analyzeRootCause(symptom, model = null) {
  const res = await fetch(`${API_BASE}/ai/root-cause-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ symptom, model }),
  });
  if (!res.ok) throw new Error('Root cause analysis failed');
  return res.json();
}

/**
 * Local incident detection (error bursts, novel templates, escalation chains).
 * No LLM involved — runs on the backend store in milliseconds.
 */
export async function detectIncidents(options = {}) {
  const res = await fetch(`${API_BASE}/detect/incidents`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options),
  });
  if (!res.ok) throw new Error('Incident detection failed');
  return res.json();
}

/**
 * Open the real-time SSE feed. Returns an EventSource (call .close() to stop).
 * onEvent receives parsed payloads: { type:'snapshot'|'log'|'alert', ... }.
 */
export function openRealtimeStream(onEvent, onError) {
  const es = new EventSource(`${API_BASE}/realtime/stream`);
  es.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data));
    } catch { /* ignore malformed frames */ }
  };
  if (onError) es.onerror = onError;
  return es;
}

/**
 * Recent realtime events + alerts + counters.
 */
export async function getRealtimeSnapshot() {
  const res = await fetch(`${API_BASE}/realtime/snapshot`);
  return res.json();
}

/**
 * Clear the realtime feed.
 */
export async function clearRealtime() {
  const res = await fetch(`${API_BASE}/realtime/clear`, { method: 'POST' });
  return res.json();
}

/**
 * List available demo actions.
 */
export async function getDemoActions() {
  const res = await fetch(`${API_BASE}/demo/actions`);
  return res.json();
}

/**
 * Fire `count` lines of a demo action into the realtime feed.
 */
export async function triggerDemo(action, count = 1) {
  const res = await fetch(`${API_BASE}/demo/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, count }),
  });
  if (!res.ok) throw new Error('Demo trigger failed');
  return res.json();
}

/**
 * Start/stop the auto-stream. Body: { running, action?, rate? }
 */
export async function controlDemoStream(body) {
  const res = await fetch(`${API_BASE}/demo/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('Stream control failed');
  return res.json();
}

// ── Dataset demo (standalone /demo page) ────────────────────────────────

/**
 * List available dataset-demo sources (data/ logs + v2 training datasets).
 */
export async function getDatasetDemoSources() {
  const res = await fetch(`${API_BASE}/demo-dataset/sources`);
  if (!res.ok) throw new Error('Failed to load dataset sources');
  return res.json();
}

/**
 * Fire `count` sniffed lines from the chosen source into the realtime hub.
 */
export async function triggerDatasetDemo(count = 50, source) {
  const res = await fetch(`${API_BASE}/demo-dataset/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ count, source }),
  });
  if (!res.ok) throw new Error('Dataset demo trigger failed');
  return res.json();
}

/**
 * Start/stop the dataset auto-stream. Body: { running, source?, rate? }
 */
export async function controlDatasetDemoStream(body) {
  const res = await fetch(`${API_BASE}/demo-dataset/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('Dataset stream control failed');
  return res.json();
}
