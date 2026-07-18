# AIzen - Detailed Project Prompt

You are an expert full-stack developer and system architect. Your task is to perfectly recreate **AIzen**, an intelligent log analysis engine. Follow the exact specifications, structure, and libraries outlined below.

## Overview
AIzen is an AI-powered SIEM (Security Information and Event Management) platform. It parses server logs (Apache Error/Access), categorizes them using AI, creates chronological incident timelines, and generates Root Cause Analysis (RCA).

## 1. Monorepo Directory Structure
Generate the files exactly matching this structure:

```
AIzen/
├── client/
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       ├── index.css
│       ├── main.jsx
│       ├── api.js
│       ├── assets/
│       ├── components/  (Radix UI / custom shadcn-style components)
│       └── lib/
└── server/
    ├── package.json
    ├── .env
    ├── index.js
    ├── ai/
    │   ├── aiClient.js
    │   ├── promptTemplates.js
    │   └── responseParser.js
    ├── config/
    ├── middleware/
    ├── parsers/
    ├── routes/
    ├── services/
    │   ├── classificationService.js
    │   ├── contextSelector.js
    │   ├── preprocessor.js
    │   ├── rootCauseService.js
    │   └── timelineService.js
    ├── store/
    ├── uploads/
    └── utils/
```

## 2. Dependencies & Tech Stack

**Backend (`server/package.json`):**
- Node.js (Express `^4.21.2`)
- `multer` (`^1.4.5-lts.1`) for streaming file uploads.
- `cors`, `dotenv`, `express-rate-limit`.
- `winston` for internal logging.
- `zod` for validation.
- Standard HTTP clients or native Google GenAI SDKs for model interactions.

**Frontend (`client/package.json`):**
- React 19 / Vite 8
- Tailwind CSS v4 (`tailwindcss`, `@tailwindcss/postcss`)
- Icons: `lucide-react`
- UI Primitives: `@radix-ui/react-slot`, `@radix-ui/react-tabs`
- Utilities: `clsx`, `tailwind-merge`, `class-variance-authority`, `tailwindcss-animate`

## 3. Backend Core Logic Implementation

### The Context Selector (`server/services/contextSelector.js`)
This is the most critical logic. Raw logs are too big for LLMs. Implement:
1. **Deduplication:** Hash log messages while stripping out dynamic variables (IPs, ports, IDs). E.g., `Connection refused on port <NUM>`.
2. **Time Windowing:** Group logs into buckets (e.g., hourly).
3. **Target Context Extraction:** Given a specific error timestamp, pull exactly ±5 lines of logs from the `store` to provide local context without sending the whole file.

### AI Integration (`server/ai/`)
1. **`aiClient.js`**: Implement a standard interface that calls Google Gemini. It must implement a fallback to an OpenAI-compatible endpoint (like NVIDIA NIM) if Gemini fails or rate-limits.
2. **Interception/Mocking**: In `aiClient.js`, every request payload (system prompt, user prompt) and the raw LLM response MUST be written to disk in `mocks/api_calls/call_[TIMESTAMP].json`. This allows offline testing.
3. **`promptTemplates.js`**: Define 3 strict prompts:
   - Classification Prompt
   - Timeline Generation Prompt
   - Root Cause Analysis Prompt
   All prompts must strictly demand `response_format: { type: 'json_object' }`.
4. **`responseParser.js`**: Implement robust error handling to extract JSON from LLM outputs (strip markdown code blocks, fix trailing commas).

### Streaming Uploads (`server/services/preprocessor.js`)
- Expose an endpoint using `multer` that saves the uploaded `.log` file to `uploads/`.
- Use Node.js `readline` and `fs.createReadStream` to parse the file line-by-line.
- Push parsed lines into an in-memory `store` to avoid blocking the event loop.
- Use regex to detect if the log is Apache Error or Apache Access.

## 4. Frontend Architecture

### `client/src/App.jsx`
Create a wizard-like flow handling the three stages:
1. **Upload & Classify:** Drag-and-drop file upload. Display categorization results (e.g., Startup, Error, Security).
2. **Incident Timeline:** Display the parsed timeline data in a chronological UI.
3. **Root Cause Analysis:** Show High/Medium/Low priority action items and the identified root cause.

### UI Design
Use a modern, dark-mode focused aesthetic. Use `lucide-react` icons for states (loading, success, error). Ensure all styling maps to the Tailwind v4 utility classes.

### API Integration (`client/src/api.js`)
Create modular fetch functions:
- `uploadLogFile(file)`
- `getClassification(sessionId)`
- `getTimeline(sessionId)`
- `getRootCause(sessionId)`

## 5. System Deployment
- Ensure the Node server listens on `process.env.PORT`.
- Ensure Vite is configured to use environment variables for the API host URL to support deployment on Vercel (client) and Render (backend).

## 6. Required API Output Schemas
The LLM integration must strictly output JSON matching these schemas. The frontend expects this exact structure:

**1. Classification API (`/api/classify`)**
```json
[
  {
    "id": "pattern_id",
    "category": "Error",
    "confidence": 85,
    "severity": "medium",
    "explanation": "Brief technical reason",
    "insight": "Operator insight"
  }
]
```

**2. Incident Timeline API (`/api/timeline`)**
```json
{
  "timeline": [
    {
      "timestamp": "12:05 PM 10/07/2026",
      "eventTitle": "Short descriptive title",
      "severity": "error",
      "summary": "Detailed explanation",
      "escalationPath": [
         { "level": "info", "description": "...", "timestamp": "..." }
      ],
      "supportingEvidence": ["Pattern 1"],
      "affectedComponents": ["component names"]
    }
  ],
  "overallSummary": "High-level summary"
}
```

**3. Root Cause Analysis API (`/api/root-cause`)**
```json
{
  "rootCause": "Clear description of the root cause",
  "evidence": [
    {
      "finding": "What was observed",
      "logPattern": "Specific log pattern supporting this",
      "occurrences": 42,
      "significance": "Why this matters"
    }
  ],
  "causalChain": [
    "Step 1: Initial trigger",
    "Step 2: What it caused",
    "Step 3: Cascading effect"
  ],
  "impact": "Description of the impact on the system and users",
  "recommendations": [
    {
      "action": "Specific action to take",
      "priority": "high",
      "rationale": "Why this action is recommended"
    }
  ],
  "confidence": 91,
  "analysisNotes": "Any additional observations or caveats"
}
```

By following this prompt exactly, you will generate a fully functioning, 1:1 clone of the AIzen log intelligence engine.
