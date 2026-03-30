/**
 * AI Guardian – Smart Threat Detection & Awareness System
 * server.js – Main Express server
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./config/db');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting – 30 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a moment.' },
});
app.use('/api', limiter);

// ─── Input Validation ─────────────────────────────────────────────────────────
function validateInput(input) {
  if (!input || typeof input !== 'string') return false;
  const trimmed = input.trim();
  if (trimmed.length < 3) return false;
  if (trimmed.length > 2000) return false;
  return trimmed;
}

// ─── OpenAI Analysis ─────────────────────────────────────────────────────────
async function analyzeWithOpenAI(input) {
  const OpenAI = require('openai');
  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  const systemPrompt = `You are an elite cybersecurity AI trained to detect threats, scams, phishing, and malicious content in text and URLs.

Analyze the user's input and respond ONLY with a valid JSON object (no markdown, no extra text) in this exact format:
{
  "status": "Safe" | "Suspicious" | "Malicious",
  "confidence": <integer 0-100>,
  "explanation": "<clear 1-2 sentence explanation of WHY>",
  "keywords": ["<keyword1>", "<keyword2>", ...]
}

STRICT RULES — follow these exactly:

ALWAYS return "Malicious" (confidence 85-99) if input contains ANY of:
- Malware keywords: trojan, ransomware, malware, virus, exploit, hacked, inject, keylogger, rootkit, spyware, botnet, backdoor, payload, zero-day
- Typosquatted domains: paypa1, g00gle, amaz0n, micros0ft, app1e, or any brand misspelling
- Credential harvesting paths: /enter-password, /verify-account, /secure-login, /login-secure
- Phishing phrases: "your account will be suspended", "verify your account immediately", "enter your bank details", "urgent action required"
- Raw IP addresses as URLs: http://192.168.x.x or similar
- URL shorteners hiding destination: bit.ly, tinyurl, goo.gl

ALWAYS return "Suspicious" (confidence 50-80) if input contains:
- Urgency without malware: "limited time", "act now", "expires soon"
- Unusual login warnings without clear phishing
- HTTP (non-HTTPS) links
- Domains with excessive hyphens or long subdomains

ALWAYS return "Safe" (confidence 80-98) if:
- Input is normal text, a known legitimate URL, or everyday content
- No threat indicators present

keywords: list up to 8 specific suspicious words, domain parts, or threat indicators found. If URL, include the domain.`;


  const response = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: `Analyze this input for threats:\n\n${input}` },
    ],
    max_tokens: 400,
    temperature: 0.2,
  });

  const raw = response.choices[0].message.content.trim();
  // Strip markdown code fences if present
  const clean = raw.replace(/```json|```/g, '').trim();
  return JSON.parse(clean);
}

// ─── HuggingFace Fallback ─────────────────────────────────────────────────────
async function analyzeWithHuggingFace(input) {
  const fetch = (await import('node-fetch')).default;
  const HF_TOKEN = process.env.HUGGINGFACE_API_KEY;

  // Use a zero-shot classifier as fallback
  const response = await fetch(
    'https://api-inference.huggingface.co/models/facebook/bart-large-mnli',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        inputs: input,
        parameters: {
          candidate_labels: ['safe content', 'suspicious activity', 'malicious threat'],
        },
      }),
    }
  );

  const data = await response.json();
  if (data.error) throw new Error(data.error);

  const labels = data.labels;
  const scores = data.scores;
  const topIndex = scores.indexOf(Math.max(...scores));
  const topLabel = labels[topIndex];
  const confidence = Math.round(scores[topIndex] * 100);

  let status = 'Safe';
  if (topLabel.includes('suspicious')) status = 'Suspicious';
  if (topLabel.includes('malicious')) status = 'Malicious';

  // Extract simple keywords from input
  const words = input.split(/\s+/).filter(w => w.length > 4);
  const keywords = [...new Set(words)].slice(0, 5);

  return {
    status,
    confidence,
    explanation: `HuggingFace classifier identified this content as ${topLabel} with ${confidence}% confidence.`,
    keywords,
  };
}

// ─── Main Analyze Logic ───────────────────────────────────────────────────────
async function performAnalysis(input) {
  // Try OpenAI first, fall back to HuggingFace
  if (process.env.OPENAI_API_KEY) {
    try {
      return await analyzeWithOpenAI(input);
    } catch (err) {
      console.warn('[OpenAI] Failed, trying HuggingFace fallback:', err.message);
    }
  }

  if (process.env.HUGGINGFACE_API_KEY) {
    try {
      return await analyzeWithHuggingFace(input);
    } catch (err) {
      console.warn('[HuggingFace] Failed:', err.message);
    }
  }

  // Demo mode – heuristic fallback (no API keys needed)
  return heuristicAnalysis(input);
}

// ─── Heuristic Demo Fallback (no API keys) ───────────────────────────────────
function heuristicAnalysis(input) {
  const lower = input.toLowerCase();

  // ── MALICIOUS: hard keyword override (always Malicious if found) ──
  const maliciousKeywords = [
    'trojan', 'ransomware', 'malware', 'virus', 'exploit', 'hacked',
    'inject', 'keylogger', 'rootkit', 'spyware', 'botnet', 'worm',
    'backdoor', 'payload', 'zero-day', 'zeroday', 'ddos', 'phishing',
  ];
  const foundMalwareKw = maliciousKeywords.filter(k => lower.includes(k));

  // ── MALICIOUS: URL & phishing patterns ──
  const maliciousPatterns = [
    // Typosquatting brand names (paypa1, g00gle, micros0ft, amaz0n…)
    /pay[p][a][^\w]?[1il]|paypa[1il]\b/i,
    /g[o0]{2}g[l1]e/i,
    /micr[o0]s[o0]ft/i,
    /amaz[o0]n/i,
    /app[l1]e.*[il1]d/i,
    /[a-z0-9-]+\.verify-account\./i,
    /[a-z0-9-]+\.secure-login\./i,
    /[a-z0-9-]+\.login-secure\./i,
    /enter.?password/i,
    /enter.?your.?(bank|credit|card|pin|ssn)/i,
    // Credential harvesting paths
    /\/enter[\-_]?(password|credentials|login|account)/i,
    /\/steal|\/harvest|\/grab/i,
    // Suspicious TLDs combined with login/verify/account
    /(login|verify|account|secure|update).{0,20}\.(tk|ml|ga|cf|gq|xyz|top|club|work|click|link)/i,
    // IP address as hostname
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
    // URL shorteners
    /\b(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|rb\.gy|cutt\.ly)\//i,
    // Classic phishing phrases
    /verify.your.account/i,
    /your.account.will.be.suspended/i,
    /urgent.action.required/i,
    /your.account.has.been.compromised/i,
    /bank.account.details/i,
    /click.here.immediately/i,
    /claim.your.prize/i,
    /you.have.won/i,
    /microsoft.*support.*call/i,
    /suspend.*48.hours/i,
  ];

  // ── SUSPICIOUS: moderate risk patterns ──
  const suspiciousPatterns = [
    /limited.time/i,
    /act.now/i,
    /free.gift/i,
    /congratulations/i,
    /suspicious.activity/i,
    /unusual.login/i,
    /confirm.your.identity/i,
    /update.your.information/i,
    /your.password.has.expired/i,
    /click.the.link.below/i,
    /do.not.share.this/i,
    /secret.code/i,
    // HTTP (non-HTTPS) URLs
    /^http:\/\//i,
    // Long subdomains (common in phishing)
    /https?:\/\/[a-z0-9-]{30,}\./i,
    // Many hyphens in domain (e.g. secure-login-update-now.com)
    /https?:\/\/([a-z0-9]+-){3,}/i,
  ];

  // ── Collect found keywords for display ──
  const threatWords = [
    'urgent', 'verify', 'suspend', 'click', 'free', 'winner', 'prize',
    'account', 'password', 'login', 'bank', 'credit', 'secure', 'confirm',
    'update', 'immediately', 'expired', 'locked', 'compromised', 'alert',
    ...maliciousKeywords,
  ];
  const keywords = [...new Set(threatWords.filter(w => lower.includes(w)))];

  // ── Also extract suspicious URL parts as keywords ──
  const urlMatch = input.match(/https?:\/\/([^\s/]+)/i);
  if (urlMatch) {
    const domain = urlMatch[1];
    keywords.unshift(domain);
  }

  const isMalicious =
    foundMalwareKw.length > 0 ||
    maliciousPatterns.some(p => p.test(input));

  const isSuspicious = suspiciousPatterns.some(p => p.test(input));

  if (isMalicious) {
    const reasons = [];
    if (foundMalwareKw.length > 0) reasons.push(`malware keywords: ${foundMalwareKw.join(', ')}`);
    if (/paypa[1il]|verify-account|secure-login|enter.?password/i.test(input))
      reasons.push('credential harvesting / typosquatting detected');
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input))
      reasons.push('raw IP address used as hostname');

    return {
      status: 'Malicious',
      confidence: Math.floor(Math.random() * 10) + 88,
      explanation: `High-risk threat detected. ${reasons.length > 0 ? 'Indicators: ' + reasons.join('; ') + '.' : 'Multiple malicious patterns found including impersonation, credential harvesting, or malware indicators.'}`,
      keywords: keywords.slice(0, 8),
    };
  } else if (isSuspicious) {
    return {
      status: 'Suspicious',
      confidence: Math.floor(Math.random() * 20) + 55,
      explanation: 'This input contains potentially suspicious patterns such as urgency tactics, unusual links, or requests for sensitive actions. Verify the source independently before proceeding.',
      keywords: keywords.slice(0, 5),
    };
  } else {
    return {
      status: 'Safe',
      confidence: Math.floor(Math.random() * 10) + 85,
      explanation: 'No significant threat indicators detected. Content appears to be benign.',
      keywords: keywords.slice(0, 3),
    };
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/analyze – analyze input text or URL
app.post('/api/analyze', async (req, res) => {
  try {
    const { input } = req.body;
    const clean = validateInput(input);
    if (!clean) {
      return res.status(400).json({ error: 'Input must be between 3 and 2000 characters.' });
    }

    const result = await performAnalysis(clean);

    // Validate result shape
    if (!result || !result.status || result.confidence === undefined) {
      throw new Error('Invalid analysis result shape');
    }

    // Auto-save to history
    const scan = {
      id: uuidv4(),
      input: clean,
      result,
      timestamp: new Date().toISOString(),
    };
    await db.save(scan);

    res.json({ success: true, scan });
  } catch (err) {
    console.error('[/api/analyze] Error:', err.message);
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

// GET /api/history – fetch all scan history
app.get('/api/history', async (req, res) => {
  try {
    const history = await db.getAll();
    res.json({ success: true, history });
  } catch (err) {
    console.error('[/api/history GET] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

// POST /api/history – manually save a scan
app.post('/api/history', async (req, res) => {
  try {
    const { input, result } = req.body;
    const clean = validateInput(input);
    if (!clean) return res.status(400).json({ error: 'Invalid input.' });
    if (!result || !result.status) return res.status(400).json({ error: 'Invalid result.' });

    const scan = {
      id: uuidv4(),
      input: clean,
      result,
      timestamp: new Date().toISOString(),
    };
    await db.save(scan);
    res.status(201).json({ success: true, scan });
  } catch (err) {
    console.error('[/api/history POST] Error:', err.message);
    res.status(500).json({ error: 'Failed to save scan.' });
  }
});

// DELETE /api/history/:id – delete a scan by ID
app.delete('/api/history/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id || id.length < 5) return res.status(400).json({ error: 'Invalid ID.' });

    const deleted = await db.remove(id);
    if (!deleted) return res.status(404).json({ error: 'Scan not found.' });

    res.json({ success: true, message: 'Scan deleted.' });
  } catch (err) {
    console.error('[/api/history DELETE] Error:', err.message);
    res.status(500).json({ error: 'Failed to delete scan.' });
  }
});

// GET /api/stats – summary stats
app.get('/api/stats', async (req, res) => {
  try {
    const history = await db.getAll();
    const stats = {
      total: history.length,
      safe: history.filter(s => s.result.status === 'Safe').length,
      suspicious: history.filter(s => s.result.status === 'Suspicious').length,
      malicious: history.filter(s => s.result.status === 'Malicious').length,
    };
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats.' });
  }
});

// Catch-all → serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   AI Guardian – Threat Detection     ║
  ║   Server running on port ${PORT}        ║
  ╚══════════════════════════════════════╝
  `);
});

module.exports = app;