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
  const isUrl = activeMode === 'url';
  const maximum = isUrl ? 2048 : 200000;
  document.querySelector('#char-count').textContent = `${currentInput().value.length.toLocaleString()} / ${maximum.toLocaleString()}`;
  document.querySelector('#input-guidance').textContent = isUrl
    ? 'The address is checked as text; VIGIL will not visit the website.'
    : activeMode === 'html'
      ? 'HTML is scanned for visible and hidden instructions · Analysis stays on this device'
      : 'Your message is analyzed on this device · It is not sent to a cloud service';
}

function setMode(mode) {
  if (!Object.hasOwn(contentInputs, mode) || mode === activeMode) return;
  activeMode = mode;
  if (window.visionModeExit) window.visionModeExit(); // let Vision close cleanly first
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
  themeToggle.setAttribute('aria-pressed', String(dark));
  themeToggle.setAttribute('aria-label', action);
  themeToggle.title = action;
  document.querySelector('meta[name="theme-color"]').content = dark ? '#101713' : '#f3f5f1';
  if (persist) {
    try { localStorage.setItem('vigil-theme', dark ? 'dark' : 'light'); } catch { /* Theme still works for this page view. */ }
  }
}

applyTheme(document.documentElement.dataset.theme || 'light');
themeToggle.addEventListener('click', () => {
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true);
});

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (event) => {
  let hasSavedTheme = false;
  try { hasSavedTheme = Boolean(localStorage.getItem('vigil-theme')); } catch { /* Follow system when storage is unavailable. */ }
  if (!hasSavedTheme) applyTheme(event.matches ? 'dark' : 'light');
});

async function refreshModelStatus() {
  const status = document.querySelector('#ollama-status');
  const label = status.querySelector('.local-status-label');
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

/* --- Scanner navigation: the topbar Scanner link opens VIGIL Vision ------- */

const scannerSection = document.querySelector('#scanner');

function highlightScanner() {
  if (!scannerSection) return;
  scannerSection.classList.remove('panel-highlight');
  void scannerSection.offsetWidth; /* restart the pulse animation */
  scannerSection.classList.add('panel-highlight');
  window.setTimeout(() => scannerSection.classList.remove('panel-highlight'), 1800);
}

function goToScanner(event) {
  if (event) event.preventDefault();
  if (history.replaceState) history.replaceState(null, '', '#scanner');
  if (scannerSection) scannerSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  // Screenshots are VIGIL Vision's job now: land the user directly on it.
  if (window.visionModeEnter) window.visionModeEnter();
  const heading = document.querySelector('#input-heading');
  if (heading) heading.focus({ preventScroll: true });
  highlightScanner();
}

function bindAnchorNav() {
  const link = document.querySelector('.topbar-nav a[href="#scanner"]');
  if (link) link.addEventListener('click', goToScanner);
  window.addEventListener('hashchange', () => {
    if (location.hash === '#scanner') goToScanner();
  });
  if (location.hash === '#scanner') goToScanner();
}
bindAnchorNav();

modeButtons.forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));
Object.values(contentInputs).forEach((input) => input.addEventListener('input', () => {
  if (input === currentInput()) {
    updateCount();
    clearResult();
  }
}));
clearButton.addEventListener('click', () => {
  currentInput().value = '';
  updateCount();
  clearResult();
  currentInput().focus();
});
updateCount();

function clearResult() {
  analysisGeneration += 1;
  document.querySelector('#result').classList.add('hidden');
  document.querySelector('#empty-state').classList.remove('hidden');
}
window.clearResult = clearResult; // VIGIL Vision reuses this reset

function setBusy(button, busy, label) {
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
  document.querySelector('#empty-state').classList.add('hidden');
  const result = document.querySelector('#result');
  result.classList.remove('hidden');
  result.classList.remove('is-error');
  document.querySelector('.model-card').classList.remove('hidden');
  document.querySelector('#verification-note').classList.remove('hidden');
  document.querySelector('.evidence-heading').classList.remove('hidden');
  document.querySelector('#evidence-list').classList.remove('hidden');
  document.querySelector('.result-tools').classList.remove('hidden');
  document.querySelector('#result-label').textContent = label;
  const model = data.local_model || data.analysis?.local_model || { status: 'offline', name: 'Ollama unavailable', signals: [] };
  document.querySelector('#model-name').textContent = `Ollama · ${model.name || 'local model'}`;
  const modelBadge = document.querySelector('#model-badge');
  const modelBadgeLabels = { connected: 'CONNECTED', pending: 'CHECKING', offline: 'RULES FALLBACK' };
  modelBadge.textContent = modelBadgeLabels[model.status] || 'RULES ONLY';
  modelBadge.className = `model-badge ${model.status === 'connected' ? 'ready' : model.status === 'pending' ? 'pending' : ''}`;
  const verification = model.verification || { status: 'not_run', checked: 0, verified: 0, rejected: 0 };
  const verificationNote = document.querySelector('#verification-note');
  const verificationCopy = document.querySelector('#verification-copy');
  const verificationIcon = document.querySelector('#verification-icon');
  verificationNote.className = `verification-note ${verification.status}`;
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
  const findings = document.querySelector('#llm-findings');
  const signals = document.querySelector('#llm-signals');
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
  const decision = document.querySelector('#decision');
  decision.textContent = data.decision;
  decision.className = `decision-pill ${data.decision.toLowerCase()}`;
  document.querySelector('#result-title').textContent = ({
    ALLOW: 'No known risk signals', WARN: 'Pause and verify', DENY: 'Do not proceed'
  })[data.decision] || 'Check result';
  const explanation = data.explanation?.text || data.reason || '';
  document.querySelector('#explanation').textContent = explanation;
  const evidence = data.evidence || data.analysis?.evidence || [];
  document.querySelector('#evidence-count').textContent = `${evidence.length} signal${evidence.length === 1 ? '' : 's'}`;
  const list = document.querySelector('#evidence-list');
  list.replaceChildren();
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
    list.append(li);
  });
  const guidance = document.querySelector('#action-guidance');
  guidance.classList.toggle('hidden', data.decision === 'ALLOW');
  const nextStep = data.decision === 'DENY'
    ? 'Stop here. Do not share credentials, private information, or money in response to this content.'
    : 'Pause and verify through a contact method you already trust before acting.';
  document.querySelector('#guidance-copy').textContent = nextStep;
  const copyButton = document.querySelector('#copy-summary');
  copyButton.textContent = 'Copy summary';
  copyButton.setAttribute('aria-label', 'Copy this decision and its evidence');
  copyButton.dataset.defaultLabel = copyButton.textContent;
  const parentButton = document.querySelector('#copy-parent');
  parentButton.textContent = 'Explain to my parent';
  parentButton.dataset.defaultLabel = parentButton.textContent;
}

reviewForm.addEventListener('submit', async (event) => {
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
    setBusy(analyzeButton, false, 'Review content');
  }
});

checkButton.addEventListener('click', async () => {
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

document.querySelector('#copy-summary').addEventListener('click', async (event) => {
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

document.querySelector('#copy-parent').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const defaultLabel = button.dataset.defaultLabel || 'Explain to my parent';
  const copyStatus = document.querySelector('#copy-status');
  const decision = document.querySelector('#decision').textContent;
  const message = decision === 'DENY'
    ? 'VIGIL says do not continue. Please do not share an OTP, password, private information, or money in response. Contact the organization using details you already trust.'
    : decision === 'WARN'
      ? 'VIGIL found something that needs a closer look. Please pause and verify with the organization using contact details you already trust before clicking, replying, or paying.'
      : 'VIGIL did not find known warning signs, but that does not prove this message or website is safe. Check the sender and link before acting.';
  try {
    await copyPlainText(message);
    button.textContent = 'Copied for sharing';
    copyStatus.textContent = 'The plain-language explanation is copied and ready to share.';
    setTimeout(() => {
      button.textContent = defaultLabel;
      copyStatus.textContent = '';
    }, 1600);
  } catch {
    button.textContent = 'Select the explanation above';
    copyStatus.textContent = 'Clipboard access was unavailable. The plain-language explanation remains available in the page.';
    setTimeout(() => {
      button.textContent = defaultLabel;
      copyStatus.textContent = '';
    }, 2200);
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
  document.querySelector('#empty-state').classList.add('hidden');
  const result = document.querySelector('#result');
  result.classList.remove('hidden');
  result.classList.add('is-error');
  document.querySelector('.model-card').classList.add('hidden');
  document.querySelector('#verification-note').classList.add('hidden');
  document.querySelector('#llm-findings').classList.add('hidden');
  document.querySelector('.evidence-heading').classList.add('hidden');
  document.querySelector('#evidence-list').classList.add('hidden');
  document.querySelector('.result-tools').classList.add('hidden');
  document.querySelector('#result-label').textContent = label;
  document.querySelector('#decision').textContent = 'CHECK';
  document.querySelector('#decision').className = 'decision-pill warn';
  document.querySelector('#result-title').textContent = title;
  document.querySelector('#explanation').textContent = message;
  document.querySelector('#evidence-list').replaceChildren();
  document.querySelector('#evidence-count').textContent = '';
  document.querySelector('#action-guidance').classList.add('hidden');
}
