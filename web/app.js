/* ── Parent Explainer: signal → plain language mapping ── */
const PARENT_SIGNALS = {
  sensitive_request: {
    icon: '🔑', label: 'Asking for your password or code',
    explain: 'They are asking for a password, OTP, or verification code. Real organisations will never ask for this by message.',
    tips: [
      'Never share OTPs, passwords, or PINs through messages — banks and companies will never ask.',
      'If you already shared something, change your password immediately and enable two-factor authentication.'
    ]
  },
  payment_request: {
    icon: '💰', label: 'Asking you to send money',
    explain: 'They want you to send money or make a payment. Scammers often create fake invoices or urgent payment requests.',
    tips: [
      'Verify payment requests by calling the person or company directly using a number you already trust.',
      'If you already sent money, contact your bank immediately — they may be able to reverse the transaction.'
    ]
  },
  urgency: {
    icon: '⏰', label: 'Rushing you to act quickly',
    explain: 'They are using urgent language like "immediately" or "your account will be blocked." Scammers rush you so you do not have time to think.',
    tips: [
      'Take a breath. Real deadlines come with official letters or app notifications, not surprise messages.',
      'Call the organisation using a number from their official website — not from this message.'
    ]
  },
  hidden_instruction: {
    icon: '👻', label: 'Hidden commands found in this page',
    explain: 'The page contains invisible text designed to secretly control an AI assistant. This is a sophisticated attack technique.',
    tips: [
      'Do not paste content from this page into any AI tool or chatbot.',
      'Leave this page and do not interact with it further.'
    ]
  },
  instruction_text: {
    icon: '🤖', label: 'Trying to manipulate an AI',
    explain: 'This content contains commands that attempt to override AI safety rules or extract private information.',
    tips: [
      'Do not paste this into any AI assistant — it could trick the AI into revealing your information.',
      'Report this content if you received it from someone.'
    ]
  },
  link_destination_mismatch: {
    icon: '🔗', label: 'Link goes to a different website',
    explain: 'A link in this content claims to go to one website but actually opens a completely different one. This is a classic phishing trick.',
    tips: [
      'Never click links in suspicious messages. Instead, open your browser and type the website address yourself.',
      'Check where a link actually goes by hovering over it (on a computer) before clicking.'
    ]
  },
  url_ip_host: {
    icon: '🌐', label: 'Uses a number address instead of a website name',
    explain: 'Instead of a normal website name like "yourbank.com", this link goes to a raw number address. Legitimate organisations do not do this.',
    tips: ['Do not visit this link. Real companies always use proper website names, not number addresses.']
  },
  url_punycode: {
    icon: '👀', label: 'Website name uses lookalike letters',
    explain: 'The website name uses special characters that look like English letters but are not. This tricks you into thinking you are visiting a real site.',
    tips: ['Always type website addresses directly into your browser instead of clicking links in messages.']
  },
  url_confusable: {
    icon: '👀', label: 'Website name uses lookalike letters',
    explain: 'The website name contains characters that closely resemble Latin letters. This is designed to impersonate a legitimate website.',
    tips: ['Always type website addresses directly into your browser instead of clicking links in messages.']
  },
  url_userinfo: {
    icon: '⚠️', label: 'Link hides login details',
    explain: 'This link embeds what looks like login information before the real website address. This is a technique used to disguise malicious links.',
    tips: ['Do not click this link. Report the message to the sender platform.']
  },
  url_insecure_transport: {
    icon: '🔓', label: 'Unencrypted connection',
    explain: 'This link uses an unencrypted connection (http instead of https). Information you send could be intercepted.',
    tips: ['Only enter personal information on websites that show a padlock icon and use https.']
  },
  local_llm_signal: {
    icon: '🔎', label: 'Additional concern found by AI review',
    explain: 'The local AI model found an additional pattern that may indicate a risk.',
    tips: ['Verify the content through a trusted channel before acting on it.']
  }
};

const PARENT_SUMMARIES = {
  DENY: '⛔ This is dangerous. Someone is trying to deceive you. Do not respond, do not click any links, and do not share any personal information or money.',
  WARN: '⚠️ Be careful with this. There are some warning signs. Before doing anything, call the organisation directly using a phone number you already have (not one from this message).',
  ALLOW: '✅ No obvious warning signs were found. However, no tool can guarantee something is completely safe. If anything feels off, trust your instincts and verify before acting.'
};

const UNIVERSAL_TIPS = [
  'When in doubt, search for the organisation\'s official website and contact them directly.',
  'Never make decisions based on a single message — scammers rely on you not checking.'
];

function generateParentExplanation(data) {
  const decision = data.decision || 'ALLOW';
  const evidence = data.evidence || data.analysis?.evidence || [];

  const detected = new Set();
  for (const item of evidence) {
    if (item.severity !== 'info') detected.add(item.type);
  }

  // Build a natural conversational summary
  let summary;
  const actions = [];

  if (decision === 'DENY') {
    const parts = [];
    if (detected.has('sensitive_request')) parts.push('asking for your password or verification code');
    if (detected.has('payment_request')) parts.push('trying to get you to send money');
    if (detected.has('urgency')) parts.push('using threatening language to rush you');
    if (detected.has('hidden_instruction') || detected.has('instruction_text')) parts.push('hiding commands designed to trick an AI assistant');
    if (detected.has('link_destination_mismatch')) parts.push('using a link that pretends to go somewhere safe but actually goes somewhere else');
    if (detected.has('url_ip_host')) parts.push('using a suspicious number-based web address instead of a real website name');
    if (detected.has('url_punycode') || detected.has('url_confusable')) parts.push('using lookalike letters in a web address to impersonate a real website');

    if (parts.length === 0) {
      summary = 'This content has serious warning signs. Do not interact with it — do not reply, click links, or share any information.';
    } else if (parts.length === 1) {
      summary = `This content is ${parts[0]}. This is a known scam technique. Do not respond or interact with it.`;
    } else {
      const last = parts.pop();
      summary = `This content is ${parts.join(', ')} and ${last}. These are known scam techniques. Do not respond or interact with it.`;
    }

    actions.push({ icon: '🚫', text: 'Do not reply, click any links, or share information.' });
    if (detected.has('sensitive_request')) actions.push({ icon: '🔐', text: 'If you already shared a password or code, change it now and enable two-factor authentication.' });
    if (detected.has('payment_request')) actions.push({ icon: '🏦', text: 'If you already sent money, contact your bank immediately.' });
    actions.push({ icon: '📞', text: 'To verify, contact the organisation using a number you already trust — not one from this message.' });

  } else if (decision === 'WARN') {
    const parts = [];
    if (detected.has('urgency')) parts.push('uses urgent language');
    if (detected.has('payment_request')) parts.push('mentions a payment');
    if (detected.has('url_insecure_transport')) parts.push('includes an insecure link');
    if (detected.has('url_ip_host')) parts.push('includes a suspicious web address');
    if (detected.has('url_punycode') || detected.has('url_confusable')) parts.push('uses lookalike letters in a web address');

    if (parts.length === 0) {
      summary = 'Something about this content needs a closer look. It may be fine, but it is worth double-checking before you act on it.';
    } else {
      summary = `This content ${parts.join(' and ')}. It might be legitimate, but these are patterns often used in scams. Take a moment to verify before acting.`;
    }

    actions.push({ icon: '⏸️', text: 'Pause — do not act on this right away.' });
    actions.push({ icon: '📞', text: 'Call the person or organisation directly using a number you already have.' });

  } else {
    summary = 'No obvious warning signs were found. That said, no tool catches everything — if something feels off, trust your instincts.';
    actions.push({ icon: '👍', text: 'Looks okay, but stay cautious with any unexpected requests.' });
  }

  return { summary, summaryClass: `parent-${decision.toLowerCase()}`, actions };
}

function parentExplanationAsText(data) {
  const info = generateParentExplanation(data);
  const lines = ['VIGIL Safety Check', '', info.summary, ''];
  if (info.actions.length) {
    lines.push('What to do:');
    for (const a of info.actions) lines.push(`${a.icon} ${a.text}`);
  }
  return lines.join('\n');
}

/* ── App state ── */
const contentInputs = {
  message: document.querySelector('#content-message'),
  url: document.querySelector('#content-url'),
  html: document.querySelector('#content-html')
};
const modeButtons = [...document.querySelectorAll('[data-mode]')];
const analyzeButton = document.querySelector('#analyze');
const reviewForm = document.querySelector('#review-form');
const checkButton = document.querySelector('#check-action');
const clearButton = document.querySelector('#clear-input');
const themeToggle = document.querySelector('#theme-toggle');
let analysisGeneration = 0;
let activeMode = 'message';

function currentInput() {
  return contentInputs[activeMode];
}

function getSubmittedContent() {
  const value = currentInput().value.trim();
  if (!value) return '';
  if (activeMode !== 'url') return value;
  const normalized = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  let parsed;
  try { parsed = new URL(normalized); } catch { throw new Error('Enter a valid website address, such as https://example.com.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    throw new Error('Enter a valid HTTP or HTTPS website address.');
  }
  return parsed.href;
}

function updateCount() {
  const inputEl = currentInput();
  if (!inputEl) return;
  const isUrl = activeMode === 'url';
  const maximum = isUrl ? 2048 : 200000;
  const charCountEl = document.querySelector('#char-count');
  const inputGuidanceEl = document.querySelector('#input-guidance');
  if (charCountEl) charCountEl.textContent = `${inputEl.value.length.toLocaleString()} / ${maximum.toLocaleString()}`;
  if (inputGuidanceEl) {
      inputGuidanceEl.textContent = isUrl
        ? 'The address is checked as text; VIGIL will not visit the website.'
        : activeMode === 'html'
          ? 'HTML is scanned for visible and hidden instructions · Analysis stays on this device'
          : 'Your message is analyzed on this device · It is not sent to a cloud service';
  }
}

function setMode(mode) {
  if (!Object.hasOwn(contentInputs, mode) || mode === activeMode) return;
  activeMode = mode;
  modeButtons.forEach((button) => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });
  document.querySelectorAll('[data-input-panel]').forEach((panel) => {
    panel.hidden = panel.dataset.inputPanel !== mode;
  });
  updateCount();
  clearResult();
  currentInput().focus({ preventScroll: true });
}

function applyTheme(theme, persist = false) {
  const dark = theme === 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const action = dark ? 'Switch to light theme' : 'Switch to dark theme';
  if (themeToggle) {
    themeToggle.setAttribute('aria-pressed', String(dark));
    themeToggle.setAttribute('aria-label', action);
    themeToggle.title = action;
  }
  // Optional page metadata — the multi-page frontend may not include it.
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  if (themeMeta) themeMeta.content = dark ? '#171512' : '#f3f5f1';
  // Toggle icon reflects the target theme (🌙 → switch to dark shown on light).
  if (themeToggle) themeToggle.textContent = dark ? '☀️' : '🌙';
  if (persist) {
    try { localStorage.setItem('vigil-theme', dark ? 'dark' : 'light'); } catch { /* Theme still works for this page view. */ }
  }
}

// Theme is owned by /theme.js on every page (single source of truth); app.js
// only refreshes the optional theme-color meta if the theme ever changes here.
document.addEventListener('vigil-theme-changed', () => {
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  if (themeMeta) {
    themeMeta.content = document.documentElement.dataset.theme === 'dark' ? '#171512' : '#f3f5f1';
  }
});

async function refreshModelStatus() {
  const status = document.querySelector('#ollama-status');
  if (!status) return;
  const label = status.querySelector('.local-status-label');
  if (!label) return;
  try {
    const response = await fetch('/api/model');
    const model = await response.json();
    const ready = model.status === 'ready';
    status.className = `local-status ${ready ? 'ready' : 'offline'}`;
    label.textContent = ready ? `LOCAL MODEL READY · ${model.model}` : model.status === 'offline'
      ? 'RULE-BASED REVIEW · MODEL OFFLINE'
      : `RULE-BASED REVIEW · ${model.model} NOT INSTALLED`;
    status.title = ready
      ? 'The model is installed locally. VIGIL verifies inference during each review and falls back to rule-based checks if it does not respond.'
      : `Start Ollama and make ${model.model} available to enable local AI review.`;
  } catch {
    status.className = 'local-status offline';
    label.textContent = 'LOCAL RULES ONLY';
    status.title = 'Ollama could not be reached. VIGIL can still review content with local rules.';
  }
}
refreshModelStatus();

modeButtons.forEach((button) => button?.addEventListener('click', () => setMode(button.dataset.mode)));
Object.values(contentInputs).forEach((input) => input?.addEventListener('input', () => {
  if (input === currentInput()) {
    updateCount();
    clearResult();
  }
}));
clearButton?.addEventListener('click', () => {
  currentInput().value = '';
  updateCount();
  clearResult();
  currentInput().focus();
});
updateCount();

function clearResult() {
  analysisGeneration += 1;
  document.querySelector('#result')?.classList.add('hidden');
  document.querySelector('#empty-state')?.classList.remove('hidden');
  document.querySelector('#parent-explainer')?.classList.add('hidden');
  document.querySelector('.model-card')?.classList.add('hidden');
  document.querySelector('#verification-note')?.classList.add('hidden');
  document.querySelector('#llm-findings')?.classList.add('hidden');
  document.querySelector('.result-tools')?.classList.add('hidden');
  document.querySelector('#model-status-chip')?.classList.add('hidden');
  const techDetails = document.querySelector('#technical-details');
  if (techDetails) techDetails.hidden = true;
}

function setBusy(button, busy, label) {
  if (!button) return;
  button.disabled = busy;
  button.setAttribute('aria-busy', String(busy));
  button.classList.toggle('is-busy', busy);
  const text = button.querySelector('[data-button-label]');
  button.dataset.original = button.dataset.original || (text?.textContent ?? button.textContent);
  if (text) text.textContent = busy ? label : button.dataset.original;
  else button.textContent = busy ? label : button.dataset.original;
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

async function pollModelReview(analysisId, generation, label) {
  while (generation === analysisGeneration) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    try {
      const response = await fetch(`/api/analysis/${encodeURIComponent(analysisId)}`, { cache: 'no-store' });
      if (!response.ok) return;
      const job = await response.json();
      if (job.status === 'pending') continue;
      if (job.status === 'complete' && generation === analysisGeneration) {
        renderResult(job.result, label);
      }
      return;
    } catch {
      return;
    }
  }
}

function renderResult(data, label = 'CONTENT ANALYSIS') {
  document.querySelector('#empty-state')?.classList.add('hidden');
  const result = document.querySelector('#result');
  if (!result) return;
  result.classList.remove('hidden');
  result.classList.remove('is-error');
  document.querySelector('#technical-details').hidden = false;
  document.querySelector('.model-card')?.classList.remove('hidden');
  document.querySelector('#verification-note')?.classList.remove('hidden');
  document.querySelector('#evidence-list')?.classList.remove('hidden');
  document.querySelector('.result-tools')?.classList.remove('hidden');
  const resultLabelEl = document.querySelector('#result-label');
  if (resultLabelEl) resultLabelEl.textContent = label;
  const model = data.local_model || data.analysis?.local_model || { status: 'offline', name: 'Ollama unavailable', signals: [] };
  const modelNameEl = document.querySelector('#model-name');
  if (modelNameEl) modelNameEl.textContent = `Ollama · ${model.name || 'local model'}`;
  const modelBadge = document.querySelector('#model-badge');
  const verification = model.verification || { status: 'not_run', checked: 0, verified: 0, rejected: 0 };
  const verificationNote = document.querySelector('#verification-note');
  const verificationCopy = document.querySelector('#verification-copy');
  const verificationIcon = document.querySelector('#verification-icon');
  if (modelBadge) {
    const modelBadgeLabels = { connected: 'CONNECTED', pending: 'CHECKING', offline: 'RULES FALLBACK' };
    modelBadge.textContent = modelBadgeLabels[model.status] || 'RULES ONLY';
    modelBadge.className = `model-badge ${model.status === 'connected' ? 'ready' : model.status === 'pending' ? 'pending' : ''}`;
  }
  if (verificationNote) verificationNote.className = `verification-note ${verification.status}`;
  if (verificationIcon && verificationCopy) {
    if (model.status === 'pending' || verification.status === 'pending') {
      verificationIcon.textContent = '◌';
      verificationCopy.textContent = 'Rules verdict is ready. The local model is checking for additional evidence.';
    } else if (verification.status === 'not_run') {
      verificationIcon.textContent = '•';
      verificationCopy.textContent = 'Local model did not respond. The displayed decision uses deterministic rules.';
    } else if (verification.rejected > 0) {
      verificationIcon.textContent = '✓';
      verificationCopy.textContent = `Independent check accepted ${verification.verified} of ${verification.checked} model findings and rejected ${verification.rejected} unsupported claim(s).`;
    } else if (verification.checked > 0) {
      verificationIcon.textContent = '✓';
      verificationCopy.textContent = `Independent check matched all ${verification.verified} model finding(s) to exact source quotes and local category rules.`;
    } else {
      verificationIcon.textContent = '✓';
      verificationCopy.textContent = 'No extra model findings. The rule-based scan still checked the content.';
    }
  }
  // Verdict-side status chip mirrors the nav chip (ready / pending / offline).
  const modelStatusChip = document.querySelector('#model-status-chip');
  if (modelStatusChip) {
    const chipLabels = { connected: 'LOCAL MODEL CHECKED', pending: 'LOCAL MODEL CHECKING', offline: 'RULES FALLBACK' };
    modelStatusChip.textContent = chipLabels[model.status] || 'RULES ONLY';
    modelStatusChip.className = `local-status ${model.status === 'connected' ? 'ready' : model.status === 'pending' ? 'pending' : 'offline'} ml-auto`;
  }
  const findings = document.querySelector('#llm-findings');
  const signals = document.querySelector('#llm-signals');
  if (findings && signals) {
    signals.replaceChildren();
    (model.signals || []).forEach((signal) => {
      const p = document.createElement('p');
      p.append(document.createTextNode(`${signal.fact}: `));
      const quote = document.createElement('q');
      quote.textContent = signal.quote;
      p.append(quote);
      signals.append(p);
    });
    findings.classList.toggle('hidden', !(model.signals || []).length);
  }
  const decisionEl = document.querySelector('#decision');
  if (decisionEl) {
    decisionEl.textContent = data.decision;
    decisionEl.className = `decision-pill ${(data.decision || 'ALLOW').toLowerCase()}`;
  }
  
  const scoreRing = document.querySelector('#safety-score-ring');
  const scoreText = document.querySelector('#safety-score-text');
  if (scoreRing && scoreText) {
    let score = 50;
    let color = '#ccc';
    if (data.decision === 'ALLOW') { score = 95; color = 'var(--success)'; }
    else if (data.decision === 'WARN') { score = 45; color = 'var(--warning-dark)'; }
    else if (data.decision === 'DENY') { score = 10; color = 'var(--danger)'; }
    scoreText.textContent = score;
    scoreText.style.color = color;
    scoreRing.style.stroke = color;
    // Animation to standard ScamAdviser score
    requestAnimationFrame(() => {
        scoreRing.style.strokeDashoffset = 251 - (251 * score / 100);
    });
  }

  // Risk meter used by the agent-guard page (safety score, inverted):
  // DENY shows a high risk number, ALLOW a low one. Backend risk only —
  // the decision mapping below is presentational.
  const riskLevel = String(data.risk || data.analysis?.risk || '').toLowerCase();
  const riskScore = riskLevel === 'high' ? 90 : riskLevel === 'medium' ? 50 : 12;
  const riskBar = document.querySelector('#risk-bar');
  const riskText = document.querySelector('#risk-score-text');
  if (riskBar) {
    riskBar.style.width = `${riskScore}%`;
    riskBar.style.background = data.decision === 'DENY' ? 'var(--deny-text, #A8321F)'
      : data.decision === 'WARN' ? 'var(--warn-text, #7A5200)' : 'var(--allow-text, #1F5B36)';
  }
  if (riskText) riskText.textContent = `${riskScore}/100`;
  const decisionIcon = document.querySelector('#decision-icon');
  if (decisionIcon) {
    decisionIcon.textContent = data.decision === 'DENY' ? '🛑' : data.decision === 'WARN' ? '⚠️' : '✅';
  }

  const titleEl = document.querySelector('#result-title');
  if (titleEl) {
    titleEl.textContent = ({
      ALLOW: 'No known risk signals', WARN: 'Pause and verify', DENY: 'Do not proceed'
    })[data.decision] || 'Check result';
  }
  
  const explanation = data.explanation?.text || data.reason || '';
  const expEl = document.querySelector('#explanation');
  if (expEl) expEl.textContent = explanation;

  const evidence = data.evidence || data.analysis?.evidence || [];
  const countEl = document.querySelector('#evidence-count');
  if (countEl) countEl.textContent = `${evidence.length} signal${evidence.length === 1 ? '' : 's'}`;

  const posList = document.querySelector('#evidence-positive');
  const negList = document.querySelector('#evidence-negative');
  const origList = document.querySelector('#evidence-list');
  
  if (posList && negList) {
    posList.replaceChildren();
    negList.replaceChildren();
    evidence.forEach((item) => {
      const li = document.createElement('li');
      li.className = item.severity;
      const fact = document.createElement('span');
      fact.className = 'evidence-fact';
      fact.textContent = item.fact;
      const kind = document.createElement('span');
      kind.className = 'evidence-type';
      kind.textContent = item.type.replaceAll('_', ' ');
      li.append(fact, kind);
      
      if (item.severity === 'info' || item.severity === 'success') {
        posList.append(li);
      } else {
        negList.append(li);
      }
    });
  } else if (origList) {
    // Fallback for agent guard which still has old list
    origList.replaceChildren();
    evidence.forEach((item) => {
      const li = document.createElement('li');
      li.className = item.severity;
      const fact = document.createElement('span');
      fact.className = 'evidence-fact';
      fact.textContent = item.fact;
      const kind = document.createElement('span');
      kind.className = 'evidence-type';
      kind.textContent = item.type.replaceAll('_', ' ');
      li.append(fact, kind);
      origList.append(li);
    });
  }
  const copyButton = document.querySelector('#copy-summary');
  if (copyButton) {
    copyButton.textContent = 'Copy technical summary';
    copyButton.setAttribute('aria-label', 'Copy this decision and its evidence');
    copyButton.dataset.defaultLabel = copyButton.textContent;
  }

  /* ── Populate parent explainer ── */
  const explainer = document.querySelector('#parent-explainer');
  if (!explainer) return;
  explainer.classList.remove('hidden');
  explainer._lastData = data;

  const info = generateParentExplanation(data);

  const summaryEl = document.querySelector('#parent-summary');
  if (summaryEl) {
    summaryEl.textContent = info.summary;
    summaryEl.className = `parent-summary ${info.summaryClass}`;
  }

  const stepsEl = document.querySelector('#parent-action-steps');
  if (stepsEl) {
    stepsEl.replaceChildren();
    for (const action of info.actions) {
      const step = document.createElement('div');
      step.className = 'parent-action-step';
      step.innerHTML = `<span class="parent-step-icon">${action.icon}</span><div class="parent-step-text">${action.text}</div>`;
      stepsEl.append(step);
    }
  }

  const waLink = document.querySelector('#share-whatsapp');
  const fullText = parentExplanationAsText(data);
  try {
    const waUrl = `https://wa.me/?text=${encodeURIComponent(fullText)}`;
    if (waLink) {
      waLink.href = waUrl;
      waLink.hidden = false;
    }
  } catch { if (waLink) waLink.hidden = true; }
}

reviewForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = currentInput();
  let submittedContent;
  try { submittedContent = getSubmittedContent(); } catch (error) {
    input.focus();
    return showError(error.message, 'INVALID WEBSITE ADDRESS', 'Check the address');
  }
  if (!submittedContent) {
    input.focus();
    return showError('Add the content you want VIGIL to review.', 'CONTENT NEEDED', 'Add content to continue');
  }
  const generation = ++analysisGeneration;
  const sourceValue = input.value;
  setBusy(analyzeButton, true, 'Checking…');
  try {
    const data = await postJson('/api/analyze', { content: submittedContent });
    if (generation !== analysisGeneration || currentInput() !== input || input.value !== sourceValue) return;
    renderResult(data);
    if (data.analysis_id) pollModelReview(data.analysis_id, generation, 'CONTENT ANALYSIS');
  } catch (error) {
    if (generation !== analysisGeneration) return;
    showError(error.message, 'REVIEW ERROR', 'Could not analyze');
  } finally {
    setBusy(analyzeButton, false, 'Analyze content');
  }
});

checkButton?.addEventListener('click', async () => {
  const input = currentInput();
  let submittedContent;
  try { submittedContent = getSubmittedContent(); } catch (error) {
    input.focus();
    return showError(error.message, 'INVALID WEBSITE ADDRESS', 'Check the address');
  }
  if (!submittedContent) {
    input.focus();
    return showError('Add content to review before checking an action.', 'CONTENT NEEDED', 'Add content to continue');
  }
  const generation = ++analysisGeneration;
  const sourceValue = input.value;
  setBusy(checkButton, true, 'Checking…');
  try {
    const data = await postJson('/api/check-action', {
      content: submittedContent,
      action: document.querySelector('#action').value
    });
    if (generation !== analysisGeneration || currentInput() !== input || input.value !== sourceValue) return;
    renderResult(data, 'AGENT ACTION REVIEW');
    if (data.analysis_id) pollModelReview(data.analysis_id, generation, 'AGENT ACTION REVIEW');
  } catch (error) {
    if (generation !== analysisGeneration) return;
    showError(error.message, 'REVIEW ERROR', 'Could not analyze');
  } finally {
    setBusy(checkButton, false, 'Check action');
  }
});

document.querySelector('#copy-summary')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const defaultLabel = button.dataset.defaultLabel || 'Copy summary';
  const copyStatus = document.querySelector('#copy-status');
  try {
    const evidence = [...document.querySelectorAll('#evidence-list .evidence-fact')]
      .map((item) => `• ${item.textContent}`);
    const text = [
      `VIGIL decision: ${document.querySelector('#decision').textContent}`,
      document.querySelector('#explanation').textContent,
      ...evidence
    ].filter(Boolean).join('\n');
    await copyPlainText(text);
    button.textContent = 'Copied';
    copyStatus.textContent = 'The decision summary and evidence were copied.';
    setTimeout(() => {
      button.textContent = defaultLabel;
      copyStatus.textContent = '';
    }, 1600);
  } catch {
    button.textContent = 'Select the explanation above';
    copyStatus.textContent = 'Clipboard access was unavailable. The result remains visible above.';
    setTimeout(() => {
      button.textContent = defaultLabel;
      copyStatus.textContent = '';
    }, 2200);
  }
});

document.querySelector('#share-copy')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const explainer = document.querySelector('#parent-explainer');
  const data = explainer._lastData;
  if (!data) return;
  const text = parentExplanationAsText(data);
  try {
    await copyPlainText(text);
    button.textContent = '✓ Copied';
    setTimeout(() => { button.textContent = '📋 Copy explanation'; }, 1600);
  } catch {
    button.textContent = 'Select text above';
    setTimeout(() => { button.textContent = '📋 Copy explanation'; }, 2200);
  }
});

async function copyPlainText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch { /* Fall through to the local document-copy fallback. */ }
  }
  const field = document.createElement('textarea');
  field.value = text;
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.opacity = '0';
  document.body.append(field);
  field.select();
  const copied = document.execCommand('copy');
  field.remove();
  if (!copied) throw new Error('Clipboard unavailable');
}

function showError(message, label = 'REVIEW ERROR', title = 'Could not analyze') {
  document.querySelector('#empty-state')?.classList.add('hidden');
  const result = document.querySelector('#result');
  if (!result) return;
  result.classList.remove('hidden');
  result.classList.add('is-error');
  document.querySelector('#parent-explainer')?.classList.add('hidden');
  document.querySelector('#technical-details').hidden = true;
  document.querySelector('.model-card')?.classList.add('hidden');
  document.querySelector('#verification-note')?.classList.add('hidden');
  document.querySelector('#llm-findings')?.classList.add('hidden');
  document.querySelector('#evidence-list')?.classList.add('hidden');
  document.querySelector('.result-tools')?.classList.add('hidden');
  document.querySelector('#model-status-chip')?.classList.add('hidden');
  const errorLabelEl = document.querySelector('#result-label');
  if (errorLabelEl) errorLabelEl.textContent = label;
  const decisionEl = document.querySelector('#decision');
  if (decisionEl) {
    decisionEl.textContent = 'CHECK';
    decisionEl.className = 'decision-pill warn';
  }
  document.querySelector('#result-title').textContent = title;
  document.querySelector('#explanation').textContent = message;
  document.querySelector('#evidence-list')?.replaceChildren();
  const errorCountEl = document.querySelector('#evidence-count');
  if (errorCountEl) errorCountEl.textContent = '';
}


async function loadTrendingScam() {
  const title = document.getElementById('trending-scam-title');
  const desc = document.getElementById('trending-scam-desc');
  const level = document.getElementById('trending-scam-level');
  if (!title) return;
  const source = document.getElementById('trending-scam-source');
  const setSource = (data) => {
    if (!source) return;
    source.textContent = data?.source === 'model'
      ? `Generated live by the local model (${data.model || 'local LLM'})`
      : 'Offline example · start Ollama to generate live threats';
  };
  try {
    const res = await fetch('/api/trending');
    const data = await res.json();
    title.textContent = data.title || 'Unknown Threat';
    desc.textContent = data.description || 'Could not load threat description.';
    level.textContent = 'Threat Level: ' + (data.threat_level || 'Unknown');
    setSource(data);
  } catch (e) {
    title.textContent = 'Delivery Fee Scam';
    desc.textContent = 'Scammers are sending SMS messages claiming a package is held due to an unpaid shipping fee. Clicking the link leads to a fake courier site designed to steal your credit card details.';
    level.textContent = 'Threat Level: High';
    setSource(null);
  }
}
loadTrendingScam();
