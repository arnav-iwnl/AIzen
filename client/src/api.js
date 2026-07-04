const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000/api';

/**
 * Upload a log file to the backend.
 */
export async function uploadLogFile(file) {
  const formData = new FormData();
  formData.append('logfile', file);

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
