/**
 * AI Guardian – script.js
 * Frontend logic: analyze, history CRUD, dark/light mode, toast, voice alert
 */

'use strict';

// ─── DOM References ───────────────────────────────────────────────────────────
const threatInput    = document.getElementById('threatInput');
const analyzeBtn     = document.getElementById('analyzeBtn');
const clearBtn       = document.getElementById('clearBtn');
const charCount      = document.getElementById('charCount');
const resultCard     = document.getElementById('resultCard');
const statusIcon     = document.getElementById('statusIcon');
const statusLabel    = document.getElementById('statusLabel');
const confidenceLabel= document.getElementById('confidenceLabel');
const resultTimestamp= document.getElementById('resultTimestamp');
const riskBar        = document.getElementById('riskBar');
const riskPct        = document.getElementById('riskPct');
const resultExplanation = document.getElementById('resultExplanation');
const keywordsWrap   = document.getElementById('keywordsWrap');
const resultInputPreview = document.getElementById('resultInputPreview');
const historyList    = document.getElementById('historyList');
const historyEmpty   = document.getElementById('historyEmpty');
const refreshHistory = document.getElementById('refreshHistory');
const themeToggle    = document.getElementById('themeToggle');
const toastContainer = document.getElementById('toastContainer');
const statsText      = document.getElementById('statsText');
const statSafe       = document.getElementById('statSafe');
const statSuspicious = document.getElementById('statSuspicious');
const statMalicious  = document.getElementById('statMalicious');
const statTotal      = document.getElementById('statTotal');
const voiceModal     = document.getElementById('voiceModal');
const modalBackdrop  = document.getElementById('modalBackdrop');
const dismissVoice   = document.getElementById('dismissVoice');

// ─── Status Emojis ───────────────────────────────────────────────────────────
const STATUS_EMOJI = { Safe: '🛡️', Suspicious: '⚠️', Malicious: '🚨' };
const STATUS_CLASS = { Safe: 'safe', Suspicious: 'suspicious', Malicious: 'malicious' };

// ─── Theme Management ─────────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem('guardian-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('guardian-theme', next);
  showToast(next === 'dark' ? 'Dark mode on' : 'Light mode on', 'success');
}

themeToggle.addEventListener('click', toggleTheme);
initTheme();

// ─── Character Count ──────────────────────────────────────────────────────────
threatInput.addEventListener('input', () => {
  const len = threatInput.value.length;
  charCount.textContent = `${len} / 2000`;
  charCount.style.color = len > 1800 ? 'var(--suspicious)' : '';
});

// ─── Clear Input ──────────────────────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  threatInput.value = '';
  charCount.textContent = '0 / 2000';
  threatInput.focus();
});

// ─── Toast Notification ───────────────────────────────────────────────────────
function showToast(message, type = 'success', duration = 3000) {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="toast-dot"></span><span>${message}</span>`;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-exit');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ─── Analyze ──────────────────────────────────────────────────────────────────
async function runAnalysis() {
  const input = threatInput.value.trim();

  if (!input || input.length < 3) {
    showToast('Please enter at least 3 characters.', 'error');
    threatInput.focus();
    return;
  }

  // Set loading state
  analyzeBtn.disabled = true;
  analyzeBtn.classList.add('loading');
  analyzeBtn.querySelector('.btn-label').textContent = 'Analyzing...';

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Analysis failed.');
    }

    renderResult(data.scan);
    showToast(`Analysis complete: ${data.scan.result.status}`, 
      data.scan.result.status === 'Safe' ? 'success' : 
      data.scan.result.status === 'Suspicious' ? 'warn' : 'error'
    );

    // Trigger voice alert for malicious
    if (data.scan.result.status === 'Malicious') {
      triggerVoiceAlert(data.scan.result.explanation);
    }

    // Refresh history & stats
    loadHistory();
    loadStats();

  } catch (err) {
    console.error(err);
    showToast(err.message || 'Something went wrong.', 'error');
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.classList.remove('loading');
    analyzeBtn.querySelector('.btn-label').textContent = 'Analyze Threat';
  }
}

analyzeBtn.addEventListener('click', runAnalysis);

// Allow Ctrl+Enter to submit
threatInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runAnalysis();
});

// ─── Render Result Card ───────────────────────────────────────────────────────
function renderResult(scan) {
  const { result, input, timestamp } = scan;
  const cls = STATUS_CLASS[result.status] || 'safe';
  const emoji = STATUS_EMOJI[result.status] || '🛡️';

  // Status icon + label
  statusIcon.className = `status-icon ${cls}`;
  statusIcon.textContent = emoji;

  statusLabel.className = `status-label ${cls}`;
  statusLabel.textContent = result.status;

  confidenceLabel.textContent = `Confidence: ${result.confidence}%`;

  // Timestamp
  resultTimestamp.textContent = formatTime(timestamp);

  // Explanation
  resultExplanation.textContent = result.explanation;

  // Scanned input preview
  resultInputPreview.textContent = input;

  // Keywords
  keywordsWrap.innerHTML = '';
  if (result.keywords && result.keywords.length > 0) {
    result.keywords.forEach((kw, i) => {
      const chip = document.createElement('span');
      chip.className = `keyword-chip ${cls}`;
      chip.textContent = kw;
      chip.style.animationDelay = `${i * 60}ms`;
      keywordsWrap.appendChild(chip);
    });
    document.getElementById('keywordsSection').style.display = '';
  } else {
    document.getElementById('keywordsSection').style.display = 'none';
  }

  // Risk Meter – animate
  const riskValue = result.confidence;
  riskPct.textContent = `${riskValue}%`;
  riskPct.style.color = `var(--${cls})`;

  // Reset bar first, then animate
  riskBar.style.width = '0%';
  riskBar.className = `risk-meter-bar ${cls}`;

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      riskBar.style.width = `${riskValue}%`;
    });
  });

  // Show card
  resultCard.classList.remove('hidden');
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Format Timestamp ─────────────────────────────────────────────────────────
function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// ─── Load History ─────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    if (!data.success) throw new Error(data.error);
    renderHistory(data.history);
  } catch (err) {
    console.error('[History] Load failed:', err.message);
  }
}

function renderHistory(history) {
  // Remove all existing items (keep the empty state element)
  const items = historyList.querySelectorAll('.history-item');
  items.forEach(el => el.remove());

  if (!history || history.length === 0) {
    historyEmpty.style.display = '';
    return;
  }

  historyEmpty.style.display = 'none';

  // Show up to 20 recent items
  history.slice(0, 20).forEach((scan, i) => {
    const item = buildHistoryItem(scan, i);
    historyList.appendChild(item);
  });
}

function buildHistoryItem(scan, delay = 0) {
  const cls = STATUS_CLASS[scan.result.status] || 'safe';
  const item = document.createElement('div');
  item.className = 'history-item';
  item.style.animationDelay = `${delay * 40}ms`;
  item.dataset.id = scan.id;

  item.innerHTML = `
    <span class="history-status-dot ${cls}"></span>
    <div class="history-content">
      <div class="history-input">${escapeHTML(scan.input)}</div>
      <div class="history-meta">
        <span class="history-badge ${cls}">${scan.result.status} · ${scan.result.confidence}%</span>
        <span>${formatTime(scan.timestamp)}</span>
      </div>
    </div>
    <button class="history-delete" title="Delete scan" data-id="${scan.id}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/>
        <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
      </svg>
    </button>
  `;

  // Delete handler
  item.querySelector('.history-delete').addEventListener('click', async (e) => {
    e.stopPropagation();
    await deleteScan(scan.id, item);
  });

  // Click to re-display result
  item.querySelector('.history-content').addEventListener('click', () => {
    renderResult(scan);
  });

  return item;
}

// ─── Delete Scan ──────────────────────────────────────────────────────────────
async function deleteScan(id, itemEl) {
  try {
    const res = await fetch(`/api/history/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || 'Delete failed');

    // Animate out
    itemEl.style.transition = 'all 0.3s ease';
    itemEl.style.opacity = '0';
    itemEl.style.transform = 'translateX(-10px)';
    setTimeout(() => {
      itemEl.remove();
      // Show empty state if no items left
      if (!historyList.querySelector('.history-item')) {
        historyEmpty.style.display = '';
      }
    }, 300);

    showToast('Scan deleted.', 'success');
    loadStats();
  } catch (err) {
    showToast(err.message || 'Delete failed.', 'error');
  }
}

refreshHistory.addEventListener('click', async () => {
  refreshHistory.disabled = true;
  await loadHistory();
  await loadStats();
  refreshHistory.disabled = false;
  showToast('History refreshed.', 'success');
});

// ─── Load Stats ───────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    if (!data.success) return;

    const { safe, suspicious, malicious, total } = data.stats;
    statSafe.textContent = safe;
    statSuspicious.textContent = suspicious;
    statMalicious.textContent = malicious;
    statTotal.textContent = total;

    statsText.textContent = `${total} scan${total !== 1 ? 's' : ''} total`;
  } catch (err) {
    console.error('[Stats] Load failed:', err.message);
  }
}

// ─── Voice Alert (ElevenLabs + Browser TTS fallback) ─────────────────────────
async function triggerVoiceAlert(explanation) {
  // Show modal
  voiceModal.classList.remove('hidden');
  modalBackdrop.classList.remove('hidden');

  // Try ElevenLabs first
  if (window.ELEVENLABS_API_KEY || false) {
    try {
      await playElevenLabsAlert(explanation);
      return;
    } catch (err) {
      console.warn('[ElevenLabs] Falling back to browser TTS:', err.message);
    }
  }

  // Browser Web Speech API fallback
  if ('speechSynthesis' in window) {
    const utterance = new SpeechSynthesisUtterance(
      `Warning! Malicious threat detected. ${explanation}`
    );
    utterance.rate = 0.9;
    utterance.pitch = 0.8;
    utterance.volume = 1;
    window.speechSynthesis.speak(utterance);
  }
}

// ElevenLabs TTS (optional bonus)
async function playElevenLabsAlert(text) {
  const VOICE_ID = 'pNInz6obpgDQGcFmaJgB'; // "Adam" voice
  const apiKey = window.ELEVENLABS_API_KEY;

  const res = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${VOICE_ID}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'xi-api-key': apiKey,
    },
    body: JSON.stringify({
      text: `Warning! Malicious threat detected. ${text}`,
      model_id: 'eleven_monolingual_v1',
      voice_settings: { stability: 0.5, similarity_boost: 0.75 },
    }),
  });

  if (!res.ok) throw new Error('ElevenLabs API error');
  const blob = await res.blob();
  const audio = new Audio(URL.createObjectURL(blob));
  audio.play();
}

dismissVoice.addEventListener('click', () => {
  voiceModal.classList.add('hidden');
  modalBackdrop.classList.add('hidden');
  window.speechSynthesis && window.speechSynthesis.cancel();
});

modalBackdrop.addEventListener('click', () => {
  voiceModal.classList.add('hidden');
  modalBackdrop.classList.add('hidden');
  window.speechSynthesis && window.speechSynthesis.cancel();
});

// ─── Utility: Escape HTML ─────────────────────────────────────────────────────
function escapeHTML(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

// ─── Example placeholders (rotate on focus) ──────────────────────────────────
const EXAMPLES = [
  'Your account will be suspended in 24 hours. Click here to verify now.',
  'Congratulations! You\'ve been selected for a $1000 Amazon gift card. Claim now!',
  'http://paypa1-secure-login.com/verify-account',
  'URGENT: Your bank account has suspicious activity. Call us immediately.',
  'Hello, this is Microsoft Support. Your computer has been hacked. Call 1-800-HELP.',
  'Check out this interesting article about climate change I found.',
  'https://github.com/anthropics/anthropic-sdk-python',
];

let exampleIndex = 0;
threatInput.addEventListener('focus', () => {
  if (!threatInput.value) {
    threatInput.placeholder = EXAMPLES[exampleIndex % EXAMPLES.length];
    exampleIndex++;
  }
});

// ─── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  await Promise.all([loadHistory(), loadStats()]);
})();
