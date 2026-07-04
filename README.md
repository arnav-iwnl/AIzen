# AIzen — Intelligent Log Analysis Engine

AIzen is an AI-powered SIEM (Security Information and Event Management) platform that automatically analyzes server logs to identify errors, generate chronological incident timelines, and determine root causes with actionable recovery steps.

## Features

1. **Log Classification:** Automatically categorizes log lines (Startup, Error, Security, etc.) using AI. Supports Apache Error and Access logs.
2. **Incident Timeline:** Groups related errors chronologically to show exactly how a failure cascaded over time.
3. **Root Cause Analysis:** Analyzes the causal chain of an incident and provides High/Medium/Low priority recovery recommendations.
4. **Smart Context Selector:** Instead of sending massive log files to the LLM, AIzen uses fingerprint deduplication, stratified sampling, and time-windowing to reduce context payloads by **~95%** while actually *improving* reasoning accuracy.
5. **Streaming Ingestion:** Securely processes 100,000+ line log files via local disk streaming to prevent server memory exhaustion.

## Tech Stack

- **Frontend:** React, Vite, Reshaped UI, Lucide React
- **Backend:** Node.js, Express
- **AI Provider:** Multi-model routing (Google Gemini as primary, with NVIDIA NIM / OpenAI compatibility for fallback)

## Quick Start (Local Development)

### Prerequisites
- Node.js 18+
- A Google Gemini API key

### 1. Backend Setup
```bash
cd server

# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Edit .env and add your Gemini API Key
# GEMINI_API_KEY=your_key_here

# Start the server (runs on port 3000)
npm run dev
```

### 2. Frontend Setup
```bash
cd client

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```

Visit `http://localhost:5173` (or the port Vite outputs) in your browser.

## Deployment

AIzen is configured for modern cloud deployments:

### Backend (Render)
The repository includes a `render.yaml` configuration. Connect your GitHub repository to Render, and it will automatically provision the Node.js Web Service.
Make sure to add your `GEMINI_API_KEY` to the Render Environment Variables.

### Frontend (Vercel)
The `client` directory is ready for Vercel. 
1. Import the project in Vercel.
2. Set the Root Directory to `client`.
3. Vercel will automatically detect Vite and configure the build settings.
4. Update the `API_BASE` in `client/src/api.js` to point to your live Render backend URL before deploying (or configure it via Vite environment variables).

## Documentation

See [docs/architecture.md](./docs/architecture.md) for a deep dive into the system design and the Context Selector algorithm.
