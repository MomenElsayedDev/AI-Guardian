# 🛡️ AI Guardian – Smart Threat Detection & Awareness System

![logo](assets/logo.png)

A hackathon-ready AI-powered threat detection web app. Analyzes text, URLs, and messages for phishing, scams, manipulation tactics, and malicious content.

---

## 🚀 Quick Start

### 1. Clone / extract the project
```bash
cd ai-guardian
```

### 2. Install dependencies
```bash
npm install
```

### 3. Configure environment
```bash
cp .env.example .env
```

Open `.env` and add your API key(s):
```env
PORT=3000
OPENAI_API_KEY=sk-...          # Recommended – best accuracy
HUGGINGFACE_API_KEY=hf_...     # Fallback option
```

> **No API keys?** The app still works with a built-in heuristic engine (keyword-based detection). Great for demos!

### 4. Run the server
```bash
# Production
npm start

# Development (auto-reload)
npm run dev
```

### 5. Open the app
```
http://localhost:3000
```

---

## 📁 Project Structure

```
ai-guardian/
├── server.js              # Express server + API routes
├── config/
│   └── db.js              # JSON file DB (MongoDB-ready)
├── public/
│   ├── index.html         # Single-page frontend
│   ├── style.css          # Full UI styles (dark/light mode)
│   └── script.js          # Frontend logic
├── data/
│   └── scans.json         # Auto-created scan history
├── package.json
├── .env.example
└── README.md
```

---

## 🔌 REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze input, auto-saves to history |
| `GET`  | `/api/history` | Fetch all scan history |
| `POST` | `/api/history` | Manually save a scan |
| `DELETE` | `/api/history/:id` | Delete a scan by ID |
| `GET`  | `/api/stats` | Summary statistics |

### POST /api/analyze
```json
// Request
{ "input": "Your account will be suspended. Click here." }

// Response
{
  "success": true,
  "scan": {
    "id": "uuid",
    "input": "...",
    "result": {
      "status": "Malicious",
      "confidence": 94,
      "explanation": "...",
      "keywords": ["suspended", "click", "urgent"]
    },
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

---

## ✨ Features

- 🤖 **AI Analysis** – OpenAI GPT-4o-mini / HuggingFace / Heuristic fallback
- 🎨 **Dark/Light Mode** – Toggle with preference saved
- 📊 **Risk Meter** – Animated 0–100% progress bar (green/yellow/red)
- 📜 **Scan History** – View, click to re-display, delete
- 🔔 **Toast Notifications** – Success/error feedback
- 🔊 **Voice Alert** – Browser TTS (+ ElevenLabs optional) on malicious detection
- 📱 **Responsive** – Mobile-friendly layout
- 🔐 **Rate Limiting** – 30 req/min per IP

---

## 🔊 ElevenLabs Voice Alert (Optional)

1. Get an API key from [elevenlabs.io](https://elevenlabs.io)
2. Add to `.env`: `ELEVENLABS_API_KEY=your-key`
3. In `public/script.js`, set `window.ELEVENLABS_API_KEY = 'your-key'` (or inject via template)

---

## 🗄️ Switching to MongoDB

In `config/db.js`, uncomment the MongoDB section at the bottom and comment out the JSON file section. Then set `MONGO_URI` in your `.env`.

---