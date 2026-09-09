# AIzen — Intelligent Log Analysis & Realtime SIEM

AIzen is an AI-powered **SIEM** that ingests server logs to identify attacks and errors, build chronological incident timelines, and determine root causes with actionable recovery steps — backed by a local deep-learning attack classifier and live breach notifications.

## Features

1. **Realtime Breach Detection:** Every ingested log line is streamed through an in-memory hub (SSE feed), classified by rule-based heuristics **and** a v2 deep ONNX classifier (XSS, SQL injection, path traversal, brute force, scanners), and surfaced in a live dashboard.
2. **Notification Bell + Telegram Alerts:** Detected attacks emit `attack` SSE events to the frontend bell and trigger rate-limited Telegram notifications to a configured channel.
3. **Log Classification & Root Cause Analysis:** Classify lines (Startup, Error, Security, …), group related errors into incident timelines, and run RCA with recovery recommendations.
4. **Smart Context Selector:** Rather than sending raw logs to an LLM, AIzen uses fingerprint deduplication, stratified sampling, and time-windowing to cut context payloads by **~95%** while improving reasoning accuracy.
5. **Streaming Ingestion:** 100K+ line files are streamed to disk line-by-line (no memory exhaustion); clients may gzip uploads (`CompressionStream`) to reduce size and pass edge WAFs.
6. **Attack Demo Lab & Vulnerable Site:** Play pre-baked attack datasets (`/api/demo/trigger`, `/api/demo/stream`) or click through an intentionally vulnerable web app whose Apache-style logs forward to the SIEM in real time.
7. **Multi-Model AI Routing:** OpenAI-compatible routing with fallback (Gemini, NVIDIA NIM, …) and an interception/mock layer for offline testing.

## Repository Layout

| Path | Purpose |
|------|---------|
| `server/` | Node/Express backend: REST + SSE APIs, parsers, rules, v2 bridge, services |
| `client/` | React 19 + Vite dashboard (Upload, Realtime, Demo Lab, RCA) |
| `vulnerable-site/` | Intentionally vulnerable Express app that feeds the SIEM |
| `v2/` | Python (PyTorch → ONNX) training/eval pipeline + runtime `onnx_classifier.js` |
| `render.yaml` | Render services for backend, frontend, and vulnerable site |

## Quick Start (Local Development)

Prerequisites: Node.js 18+.

### 1. Backend (`server/`)
```bash
cd server
npm install
cp .env.example .env   # add keys per the table below
npm run dev            # http://localhost:3000
```

### 2. Frontend (`client/`)
```bash
cd client
npm install
npm run dev            # http://localhost:5173
```

### 3. Vulnerable Site (`vulnerable-site/`)
```bash
cd vulnerable-site
npm install
npm run dev            # http://localhost:5000
```

Visit `http://localhost:5173`, open the **Realtime** view, then attack the vulnerable site (e.g. `/product?id=1' OR '1'='1`) — the attack appears live and a Telegram alert fires.

### Environment Variables (`server/.env`)

| Variable | Purpose |
|----------|---------|
| `V2_CLASSIFIER=onnx` | Enable the deep ONNX attack classifier (uses `v2/runtime/model.onnx`) |
| `V2_THRESHOLD` | Confidence threshold for flagging attacks (default `0.95`) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHANNEL_ID` | Enable Telegram alerts | 
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `AI_DEFAULT_MODEL` | LLM features (RCA); falls back to local classifier when unset |
| `FRONTEND_URL` | Allowed CORS origin |
| `UPLOAD_MAX_SIZE_MB` | Upload cap (default `50`) |
| `DATASET_BUCKET_URL` | Where demo/model assets are fetched at boot |

## Deployment

- **Backend & vulnerable site:** `render.yaml` provisions `aizen-backend`, `aizen-frontend`, and `aizen-vulnerable-site`. Connect the repo to Render; add API keys as *sync: false* secrets.
- **Frontend (Vercel):** root directory `client`, Vite auto-detected. Set `VITE_API_URL` to the live backend (e.g. `https://<backend>.onrender.com/api`) via `client/.env.production`.

## Testing

```bash
cd server && npm run smoke         # upload → classify → timeline → RCA pipeline
cd server && npm run smoke:realtime # realtime hub ingest/SSE smoke test
cd client && npm run lint && npm run build
```

## Documentation

See [docs/architecture.md](./docs/architecture.md) for a deep dive into the system design.