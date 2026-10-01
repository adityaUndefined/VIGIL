/**
 * VIGIL Security — side panel controller.
 *
 * Owns view switching, user-initiated scans, and result rendering.
 * All analysis goes through VigilAPI (src/services/api.js). The backend is
 * the only source of truth; nothing here computes risk.
 */
'use strict';

(() => {
  const { $, el, announcer, createStepList } = self.VigilUI;
  const Risk = self.VigilRisk;
  const API = self.VigilAPI;
  const CONFIG = self.VIGIL_CONFIG;

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  const state = {
    tab: null,
    busy: false,
    lastRun: null,        // re-runnable scan descriptor for [Try Again]
    selection: null,      // {text, sourceTitle}
    visionPreview: null   // preview <img> for screenshot scans
  };

  const prefs = { pageScanning: true, history: true };
  const PREF_KEY = 'vigilPrefs';

  async function loadPrefs() {
    const store = await chrome.storage.local.get({ [PREF_KEY]: prefs });
    Object.assign(prefs, store[PREF_KEY] || {});
  }

  async function savePrefs() {
    await chrome.storage.local.set({ [PREF_KEY]: prefs });
  }

  // ------------------------------------------------------------------
  // View switching
  // ------------------------------------------------------------------

  const views = ['home', 'result', 'history', 'settings'];
  let activeView = 'home';

  function showView(name) {
    for (const view of views) {
      $(`#view-${view}`).classList.toggle('hidden', view !== name);
    }
    activeView = name;
  }

  function announce(message) {
    announcer.say(message);
  }

  // ------------------------------------------------------------------
  // Backend status
  // ------------------------------------------------------------------

  async function refreshBackendStatus() {
    const dot = $('#backend-dot');
    const label = $('#backend-status');
    dot.className = 'status-dot checking';
    label.textContent = 'Checking VIGIL service…';
    $('#setting-backend-badge').className = 'backend-badge unknown';
    $('#setting-backend-badge').textContent = 'Checking';
    $('#setting-backend-detail').textContent = 'Checking…';
    $('#setting-api-url').textContent = API.apiBase;

    const health = await API.checkHealth();
    if (health.online) {
      dot.className = 'status-dot online';
      label.textContent = 'Operational';
      $('#setting-backend-badge').className = 'backend-badge ok';
      $('#setting-backend-badge').textContent = 'Operational';
      $('#setting-backend-detail').textContent = `Connected to ${API.apiBase}`;
    } else {
      dot.className = 'status-dot offline';
      label.textContent = 'Offline — start the VIGIL server';
      $('#setting-backend-badge').className = 'backend-badge down';
      $('#setting-backend-badge').textContent = 'Offline';
      $('#setting-backend-detail').textContent = `No response from ${API.apiBase}. Run "python3 app.py" in the VIGIL project.`;
    }
  }

  // ------------------------------------------------------------------
  // Home view
  // ------------------------------------------------------------------

  function isRestricted(url) {
    if (!url) return true;
    return CONFIG.RESTRICTED_URL_SCHEMES.some((scheme) => url.startsWith(scheme))
      || (!url.startsWith('http') && !url.startsWith('file:'));
  }

  /** Hostname from a URL, '' when malformed — never throws. */
  function safeHost(url) {
    try { return new URL(url).host; } catch { return ''; }
  }

  async function refreshTab() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'vigil-get-tab' });
      state.tab = response && response.ok ? response.tab : null;
    } catch {
      state.tab = null;
    }
    const title = $('#page-title');
    const urlLabel = $('#page-url');
    const scanButton = $('#scan-button');
    const captureButton = $('#capture-button');

    if (!state.tab || isRestricted(state.tab.url)) {
      title.textContent = 'Open a page to scan';
      urlLabel.textContent = 'VIGIL can scan regular web pages. Browser pages and the Chrome Web Store are off limits.';
      scanButton.disabled = true;
      captureButton.disabled = true;
    } else {
      title.textContent = state.tab.title || safeHost(state.tab.url) || 'Current page';
      urlLabel.textContent = state.tab.url;
      scanButton.disabled = !prefs.pageScanning;
      captureButton.disabled = false;
      scanButton.title = prefs.pageScanning ? 'Analyze this page with VIGIL' : 'Page scanning is disabled in Settings';
    }
  }

  // ------------------------------------------------------------------
  // Scan runners
  // ------------------------------------------------------------------

  function beginScan(kind) {
    if (state.busy) return false;
    state.busy = true;
    state.lastRun = { kind };
    showView('result');
    $('#loading-card').classList.remove('hidden');
    $('#error-card').classList.add('hidden');
    $('#result-card').classList.add('hidden');
    clearVisionPreview();
    return true;
  }

  function endScan() {
    state.busy = false;
    $('#loading-card').classList.add('hidden');
  }

  function showError(message, rerun) {
    endScan();
    $('#error-message').textContent = message;
    $('#error-card').classList.remove('hidden');
    state.lastRun = rerun || state.lastRun;
    announce(`VIGIL error. ${message}`);
  }

  function makeSteps(kind) {
    const definitions = {
      page: ['Page captured', 'Extracting relevant content', 'Checking URLs and links', 'Correlating security signals', 'Calculating risk'],
      url: ['URL captured', 'Checking domain signals', 'Correlating security signals', 'Calculating risk'],
      message: ['Message captured', 'Extracting relevant content', 'Checking URLs and patterns', 'Correlating security signals', 'Calculating risk'],
      vision: ['Image captured', 'Preparing image for analysis', 'Extracting text (OCR)', 'Detecting visual indicators', 'Analyzing URLs', 'Correlating evidence', 'Preparing security report']
    };
    const labels = definitions[kind] || definitions.message;
    return createStepList($('#loading-steps'), labels.map((label, index) => ({ key: String(index), label })));
  }

  async function runTextScan({ kind, content, subject, scope, source }) {
    if (!beginScan(kind)) return;
    const steps = makeSteps(kind);
    steps.set('0', 'done');
    steps.set('1', 'done', 'local extraction complete');
    steps.set('2', 'running');
    let data;
    try {
      data = await API.analyzeText(content);
      steps.set('2', 'done');
      steps.set('3', 'done');
      steps.set('4', 'done');
      renderTextResult(data, { kind, subject, scope, source });
      await recordHistory({ kind, source, data });
    } catch (error) {
      showError(error.message, { kind, run: () => runTextScan({ kind, content, subject, scope, source }) });
      return;
    }
    endScan();

    // The rules verdict is shown immediately. When the backend has queued an
    // optional local-model review, follow the web app's behavior and merge
    // its verified findings when the job completes.
    if (data.analysis_id && data.local_model && data.local_model.status === 'pending') {
      const token = state.lastRun;
      const refined = await API.pollAnalysis(data.analysis_id, {
        isCancelled: () => state.lastRun !== token || state.busy
      });
      if (refined && state.lastRun === token && !state.busy) {
        renderTextResult(refined, { kind, subject, scope, source });
        await recordHistory({ kind, source, data: refined, update: true });
        announce('Result updated with local model findings.');
      }
    }
  }

  async function runPageScan() {
    if (state.busy || !prefs.pageScanning) return;
    if (!beginScan('page')) return;
    const steps = makeSteps('page');
    steps.set('0', 'running');
    let pageData;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'vigil-extract-page',
        maxChars: CONFIG.MAX_PAGE_TEXT_CHARS
      });
      if (!response || !response.ok) {
        const error = new Error((response && response.error) || 'VIGIL couldn\'t analyze this page.');
        error.recoverable = false;
        throw error;
      }
      pageData = response.pageData;
      steps.set('0', 'done', pageData.title.slice(0, 40));
      steps.set('1', 'done', `${pageData.visibleTextLength.toLocaleString()} chars · ${pageData.linkCount} links · ${pageData.formCount} forms`);
      steps.set('2', 'running');
    } catch (error) {
      showError(error.message, { kind: 'page', run: runPageScan });
      return;
    }
    try {
      const data = await API.analyzePage(pageData);
      const host = safeHost(pageData.origin);
      steps.set('2', 'done');
      steps.set('3', 'done');
      steps.set('4', 'done');
      renderTextResult(data, { kind: 'page', subject: pageData.title, scope: `PAGE SCAN · ${host}`, source: host });
      await recordHistory({ kind: 'page', source: host, data });
    } catch (error) {
      showError(error.message, { kind: 'page', run: runPageScan });
      return;
    }
    endScan();
  }

  async function runSelectionScan(text) {
    if (state.busy) {
      // A scan is already running; ask the user to confirm the new scan
      // instead of silently dropping the selection.
      $('#selected-card').classList.remove('hidden');
      $('#selected-card').scrollIntoView({ block: 'nearest' });
      return;
    }
    const source = state.selection ? state.selection.sourceTitle : 'Selected text';
    await runTextScan({
      kind: 'message',
      content: text,
      subject: text.length > 140 ? `${text.slice(0, 140)}…` : text,
      scope: 'SELECTED MESSAGE',
      source
    });
  }

  // ------------------------------------------------------------------
  // VIGIL Vision (screenshot) — capture → local OCR → backend correlation
  // ------------------------------------------------------------------

  async function runVisionScan() {
    if (state.busy) return;
    if (!beginScan('vision')) return;
    const steps = makeSteps('vision');

    // Step 0 — capture visible tab.
    steps.set('0', 'running');
    let capture;
    try {
      capture = await chrome.runtime.sendMessage({ type: 'vigil-capture-tab' });
      if (!capture || !capture.ok) throw new Error((capture && capture.error) || 'Screenshot capture failed.');
      const host = capture.pageUrl ? safeHost(capture.pageUrl) : '';
      steps.set('0', 'done', host || 'screenshot');
    } catch (error) {
      showError(error.message, { kind: 'vision', run: runVisionScan });
      return;
    }

    try {
      // Steps 1-2 — decode + OCR in the panel (image never leaves the device).
      const image = await decodeDataUrl(capture.dataUrl);
      steps.set('1', 'running');
      const prepared = self.VigilVision.prepareCanvas(image, image.naturalWidth, image.naturalHeight);
      steps.set('1', 'done', 'rescaled for analysis');
      steps.set('2', 'running');
      const ocr = await self.VigilVision.runOCR(prepared.ctx, prepared.canvas.width, prepared.canvas.height, prepared.scale, {
        onStep: (detail) => steps.set('2', 'running', detail),
        onProgress: (percent) => steps.set('2', 'running', `${percent}%`)
      });
      steps.set('2', 'done', ocr.regions.length ? `${ocr.regions.length} regions · ${Math.round(ocr.meanConfidence)}% confidence` : 'no readable text');

      // Step 3 — visual structure detection (local).
      steps.set('3', 'running');
      let visual = { rectangles: [], fields: { passwordFields: 0, otpLikeFields: 0 } };
      try {
        visual = self.VigilVisual.detectVisualStructures(prepared.ctx, prepared.canvas.width, prepared.canvas.height);
        visual.rectangles = visual.rectangles.map((rect) => ({
          x: Math.round(rect.x / prepared.scale),
          y: Math.round(rect.y / prepared.scale),
          width: Math.round(rect.width / prepared.scale),
          height: Math.round(rect.height / prepared.scale),
          label: rect.label
        }));
      } catch { /* best-effort; OCR + rules still apply */ }
      steps.set('3', 'done', visual.fields.passwordFields || visual.fields.otpLikeFields
        ? `${visual.fields.passwordFields} password · ${visual.fields.otpLikeFields} OTP-style fields`
        : 'no QR or input fields found');

      // Step 4 — QR scan (local).
      steps.set('4', 'running');
      let qrCodes = [];
      try { qrCodes = self.VigilVision.scanForQRCodes(prepared.ctx, prepared.canvas.width, prepared.canvas.height, prepared.scale); } catch { /* non-fatal */ }
      steps.set('4', 'done', qrCodes.length ? `${qrCodes.length} QR code${qrCodes.length === 1 ? '' : 's'} found` : 'no QR codes found');

      // Steps 5-7 — backend correlation.
      steps.set('5', 'running');
      const sizeBytes = Math.round((capture.dataUrl.length - capture.dataUrl.indexOf(',') - 1) * 3 / 4);
      const payload = {
        image: {
          width: image.naturalWidth,
          height: image.naturalHeight,
          sizeBytes,
          type: 'image/png'
        },
        ocr,
        qr: qrCodes,
        visual: { rectangles: visual.rectangles, fields: visual.fields }
      };
      const result = await API.analyzeScreenshot(payload);
      steps.set('5', 'done');
      steps.set('6', 'done');

      const host = safeHost(capture.pageUrl);
      showVisionPreview(capture.dataUrl, 'Captured screenshot');
      renderVisionResult(result, { scope: `SCREENSHOT · VIGIL VISION${host ? ` · ${host}` : ''}`, subject: capture.pageTitle || 'Captured screenshot' });
      await recordHistory({ kind: 'vision', source: host || 'Screenshot', data: result });
    } catch (error) {
      showError(error.message, { kind: 'vision', run: runVisionScan });
      return;
    }
    endScan();
  }

  function decodeDataUrl(dataUrl) {
    return new Promise((resolve, reject) => {
      const image = new Image();
      image.onload = () => resolve(image);
      image.onerror = () => reject(new Error('The captured screenshot could not be read. Please try again.'));
      image.src = dataUrl;
    });
  }

  function showVisionPreview(dataUrl, altText) {
    clearVisionPreview();
    const img = el('img', { attrs: { src: dataUrl, alt: altText } });
    img.style.cssText = 'width:100%;max-height:220px;object-fit:contain;border:1px solid var(--border);'
      + 'border-radius:8px;background:var(--bg);margin-bottom:12px;';
    state.visionPreview = img;
  }

  function clearVisionPreview() {
    if (state.visionPreview && state.visionPreview.parentNode) state.visionPreview.remove();
    state.visionPreview = null;
  }

  // ------------------------------------------------------------------
  // Result rendering
  // ------------------------------------------------------------------

  function renderTextResult(data, meta) {
    const risk = Risk.fromDecision(data.decision);
    renderResultShell({
      scope: meta.scope,
      subject: meta.subject,
      riskClass: risk.cls,
      riskIcon: risk.icon,
      riskLabel: risk.label,
      score: null,
      confidence: '—',
      headline: risk.headline
    });

    const evidence = Array.isArray(data.evidence) ? data.evidence : [];
    const flagged = evidence.filter((item) => item.severity !== 'info' && item.id !== 'baseline');

    // Indicators (severity tagged; not color-alone: icon + text label)
    const list = $('#indicators');
    list.replaceChildren();
    if (flagged.length) {
      flagged.forEach((item) => list.append(indicatorRow(item.severity, Risk.prettifyLabel(item.type || item.id), item.fact)));
    } else {
      list.append(el('li', { cls: 'history-empty', text: 'No suspicious indicators found.' }));
    }

    // "Why" section: backend explanation + any local-model findings.
    const correlationWrap = $('#correlations');
    const safeWrap = $('#safe-summary');
    const correlationList = $('#correlation-list');
    correlationList.replaceChildren();
    const explanation = typeof data.explanation === 'string'
      ? data.explanation
      : (data.explanation && data.explanation.text) || '';

    if (data.decision === 'ALLOW') {
      correlationWrap.classList.add('hidden');
      safeWrap.classList.remove('hidden');
      const safeList = $('#safe-list');
      safeList.replaceChildren();
      const checks = evidence.filter((item) => item.severity === 'info' || item.id === 'baseline');
      if (checks.length) checks.forEach((item) => safeList.append(el('li', { text: item.fact })));
      else safeList.append(el('li', { text: 'No major phishing indicators.' }));
      safeList.append(el('li', { text: 'Domain and content structure checked by VIGIL\'s rules.' }));
    } else {
      safeWrap.classList.add('hidden');
      correlationWrap.classList.remove('hidden');
      if (explanation) {
        correlationList.append(el('li', { children: [
          el('span', { cls: 'correlation-title', text: 'VIGIL ASSESSMENT' }),
          el('span', { cls: 'correlation-summary', text: explanation })
        ] }));
      }
      const model = data.local_model;
      if (model && Array.isArray(model.signals) && model.signals.length) {
        correlationList.append(el('li', { children: [
          el('span', { cls: 'correlation-title', text: `LOCAL MODEL FINDINGS · ${model.name || 'model'}` }),
          el('span', { cls: 'correlation-summary', text: model.signals.map((s) => s.fact).join(' ') })
        ] }));
      }
    }
    announce(`${risk.label}. ${risk.aria}`);
  }

  function renderVisionResult(result, meta) {
    const risk = Risk.fromRiskLevel(result.risk && result.risk.level);
    renderResultShell({
      scope: meta.scope,
      subject: meta.subject,
      riskClass: risk.cls,
      riskIcon: risk.icon,
      riskLabel: risk.label,
      score: result.risk && typeof result.risk.score === 'number' ? result.risk.score : null,
      confidence: result.ocr && result.ocr.regionCount ? `${Math.round(result.ocr.meanConfidence)}%` : '—',
      headline: risk.headline
    });

    const indicators = Array.isArray(result.indicators) ? result.indicators : [];
    const list = $('#indicators');
    list.replaceChildren();
    const visible = indicators.filter((indicator) => indicator.severity !== 'info');
    if (visible.length) {
      visible.forEach((indicator) => {
        const detailParts = [indicator.detected, indicator.source ? `source: ${indicator.source}` : '', indicator.confidence != null ? `${indicator.confidence}% OCR confidence` : '']
          .filter(Boolean);
        list.append(indicatorRow(indicator.severity, indicator.label, detailParts.join(' · ')));
      });
    } else {
      list.append(el('li', { cls: 'history-empty', text: 'No suspicious indicators found.' }));
    }

    const correlationWrap = $('#correlations');
    const safeWrap = $('#safe-summary');
    const correlationList = $('#correlation-list');
    const safeList = $('#safe-list');
    correlationList.replaceChildren();
    safeList.replaceChildren();

    const groups = Array.isArray(result.correlated) ? result.correlated : [];
    if (risk.cls === 'risk-safe') {
      correlationWrap.classList.add('hidden');
      safeWrap.classList.remove('hidden');
      safeList.append(el('li', { text: `OCR text extracted (${result.ocr && result.ocr.regionCount ? result.ocr.regionCount : 0} regions) and checked by VIGIL's rules.` }));
      const foundUrls = result.extracted && result.extracted.urls ? result.extracted.urls.length : 0;
      safeList.append(el('li', { text: `QR codes scanned and links checked${foundUrls ? ` — ${foundUrls} URL(s) found` : ''}.` }));
      safeList.append(el('li', { text: 'No significant threats detected.' }));
      (result.confidenceNotes || []).forEach((note) => safeList.append(el('li', { text: note })));
    } else {
      safeWrap.classList.add('hidden');
      correlationWrap.classList.remove('hidden');
      groups.forEach((group) => {
        const title = typeof group === 'string' ? group : group.title;
        const summary = typeof group === 'string' ? '' : group.summary;
        correlationList.append(el('li', { children: [
          el('span', { cls: 'correlation-title', text: title || 'PATTERN DETECTED' }),
          summary ? el('span', { cls: 'correlation-summary', text: summary }) : null
        ] }));
      });
      if (Array.isArray(result.recommendedActions) && result.recommendedActions.length) {
        correlationList.append(el('li', { children: [
          el('span', { cls: 'correlation-title', text: 'RECOMMENDED ACTIONS' }),
          el('span', { cls: 'correlation-summary', text: result.recommendedActions.join(' ') })
        ] }));
      }
      (result.confidenceNotes || []).forEach((note) => {
        correlationList.append(el('li', { children: [
          el('span', { cls: 'correlation-title', text: 'OCR CONFIDENCE' }),
          el('span', { cls: 'correlation-summary', text: note })
        ] }));
      });
    }
    announce(`${risk.label}. ${risk.aria}`);
  }

  function renderResultShell({ scope, subject, riskClass, riskIcon, riskLabel, score, confidence, headline }) {
    $('#loading-card').classList.add('hidden');
    $('#error-card').classList.add('hidden');
    $('#result-card').classList.remove('hidden');

    $('#result-scope').textContent = scope;
    $('#result-subject').textContent = subject || '';

    const banner = $('#risk-banner');
    banner.className = `risk-banner ${riskClass}`;
    $('#risk-icon').textContent = riskIcon;
    $('#risk-icon').className = `risk-icon`;
    $('#risk-level').textContent = riskLabel;
    $('#risk-score').textContent = score != null ? `${score} / 100` : 'Risk level assigned by VIGIL';

    $('#result-confidence').textContent = confidence;
    $('#risk-headline').textContent = headline;

    // Keep the preview element attached between subject and banner.
    if (state.visionPreview) {
      $('#result-subject').after(state.visionPreview);
    }
  }

  function indicatorRow(severity, label, detail) {
    const cls = Risk.severityClass(severity);
    return el('li', {
      cls: `indicator-row ${cls}`,
      children: [
        el('span', { cls: 'indicator-icon', text: Risk.severityIcon(severity), attrs: { 'aria-hidden': 'true' } }),
        el('div', { cls: 'indicator-text', children: [
          el('span', { cls: 'indicator-label', text: label }),
          detail ? el('span', { cls: 'indicator-detail', text: detail }) : null,
          el('span', { cls: 'sev-tag', text: Risk.severityText(severity) })
        ] })
      ]
    });
  }

  // ------------------------------------------------------------------
  // History
  // ------------------------------------------------------------------

  async function recordHistory({ kind, source, data, update = false }) {
    if (!prefs.history) return;
    const isVision = kind === 'vision';
    const level = isVision ? (data.risk && data.risk.level) : data.risk;
    const entry = {
      kind,
      source: source || 'Scan',
      decision: data.decision,
      riskLevel: String(level || 'low').toLowerCase(),
      riskScore: isVision && data.risk && typeof data.risk.score === 'number' ? data.risk.score : null
    };
    if (update) await API.updateRecentHistory(entry);
    else await API.addScanHistory(entry);
  }

  async function renderHistory() {
    const list = $('#history-list');
    const history = await API.getScanHistory();
    list.replaceChildren();
    if (!history.length) {
      list.append(el('li', { cls: 'history-empty', text: 'No scans yet. Results you scan will appear here (metadata only).' }));
      return;
    }
    const kindLabels = { page: 'Page scan', message: 'Message scan', url: 'URL scan', vision: 'Screenshot scan' };
    for (const entry of history) {
      const risk = Risk.fromRiskLevel(entry.riskLevel);
      const pillClass = entry.riskLevel === 'high' ? 'high' : entry.riskLevel === 'medium' ? 'warn' : 'safe';
      const pillText = `${risk.label}${entry.riskScore != null ? ` · ${entry.riskScore}/100` : ''}`;
      list.append(el('li', { cls: 'history-row', children: [
        el('div', { cls: 'history-main', children: [
          el('span', { cls: 'history-label', text: entry.source || 'Scan' }),
          el('span', { cls: 'history-sub', text: `${kindLabels[entry.kind] || 'Scan'} · ${Risk.timeString(entry.at)}` })
        ] }),
        el('span', { cls: `history-pill ${pillClass}`, text: pillText })
      ] }));
    }
  }

  // ------------------------------------------------------------------
  // Settings
  // ------------------------------------------------------------------

  function renderSettings() {
    $('#setting-page-scanning').setAttribute('aria-checked', String(prefs.pageScanning));
    $('#setting-history').setAttribute('aria-checked', String(prefs.history));
    $('#setting-api-url').textContent = API.apiBase;
    refreshBackendStatus();
  }

  async function grantSiteAccess() {
    if (!state.tab || !state.tab.url || !/^https?:/i.test(state.tab.url)) {
      $('#setting-backend-detail').textContent = 'Open a regular web page first, then grant access.';
      return;
    }
    let origin;
    try { origin = new URL(state.tab.url).origin; } catch { return; }
    const response = await chrome.runtime.sendMessage({
      type: 'vigil-request-optional-permissions',
      origins: [`${origin}/*`]
    });
    $('#setting-backend-detail').textContent = response && response.ok
      ? `Access granted for ${origin}. Rescan the page.`
      : 'Access not granted. VIGIL will ask again if a scan needs it.';
  }

  // ------------------------------------------------------------------
  // Selected-text handoff (context menu)
  // ------------------------------------------------------------------

  async function pollPendingSelection() {
    try {
      const store = await chrome.storage.session.get({ vigilPendingSelection: null });
      if (store.vigilPendingSelection) {
        await chrome.storage.session.remove('vigilPendingSelection');
        receiveSelection(store.vigilPendingSelection);
      }
    } catch { /* session storage unavailable — ignore */ }
  }

  function receiveSelection(payload) {
    if (!payload || !payload.text) return;
    if (payload.id && state.lastSelectionId === payload.id) return; // dedupe deliveries
    state.lastSelectionId = payload.id || null;
    state.selection = payload;
    $('#selected-text').textContent = payload.text;
    $('#selected-source').textContent = payload.sourceTitle ? `From: ${payload.sourceTitle}` : '';
    $('#selected-card').classList.remove('hidden');
    $('#selected-card').scrollIntoView({ block: 'nearest' });
    runSelectionScan(payload.text);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'vigil-scan-selection' && message.text) {
      receiveSelection({ text: message.text, sourceTitle: message.sourceTitle || '' });
    }
  });

  // ------------------------------------------------------------------
  // Wiring
  // ------------------------------------------------------------------

  function wire() {
    $('#scan-button').addEventListener('click', runPageScan);
    $('#capture-button').addEventListener('click', runVisionScan);
    $('#paste-button').addEventListener('click', () => {
      $('#text-card').classList.remove('hidden');
      $('#text-input').focus();
    });
    $('#text-cancel').addEventListener('click', () => {
      $('#text-card').classList.add('hidden');
      $('#text-input').value = '';
    });
    $('#text-analyze').addEventListener('click', () => {
      const text = $('#text-input').value.trim();
      if (!text) { $('#text-input').focus(); return; }
      try {
        const parsed = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`);
        if (parsed.hostname.includes('.')) {
          $('#text-card').classList.add('hidden');
          $('#text-input').value = '';
          runTextScan({
            kind: 'url',
            content: parsed.href,
            subject: parsed.href,
            scope: 'URL SCAN',
            source: parsed.host
          });
          return;
        }
      } catch { /* not a URL — scan as message */ }
      $('#text-card').classList.add('hidden');
      $('#text-input').value = '';
      runTextScan({
        kind: 'message',
        content: text,
        subject: text.length > 140 ? `${text.slice(0, 140)}…` : text,
        scope: 'MESSAGE SCAN',
        source: 'Pasted text'
      });
    });

    $('#selected-rescan').addEventListener('click', () => {
      if (state.selection) runSelectionScan(state.selection.text);
    });

    $('#back-button').addEventListener('click', () => showView('home'));
    $('#error-back').addEventListener('click', () => showView('home'));
    $('#history-back').addEventListener('click', () => showView('home'));
    $('#settings-back').addEventListener('click', () => showView('home'));

    $('#try-again').addEventListener('click', () => {
      if (state.lastRun && state.lastRun.run) state.lastRun.run();
      else showView('home');
    });

    $('#history-button').addEventListener('click', async () => {
      await renderHistory();
      showView('history');
    });
    $('#settings-button').addEventListener('click', () => {
      renderSettings();
      showView('settings');
    });

    $('#clear-history').addEventListener('click', async () => {
      await API.clearScanHistory();
      await renderHistory();
    });

    self.VigilUI.bindToggle($('#setting-page-scanning'), new ProxyBox(prefs, 'pageScanning'), async () => {
      await savePrefs();
      await refreshTab();
    });
    self.VigilUI.bindToggle($('#setting-history'), new ProxyBox(prefs, 'history'), savePrefs);

    $('#grant-host').addEventListener('click', grantSiteAccess);
  }

  /** Tiny boxed reference so bindToggle can mutate a single pref. */
  function ProxyBox(obj, key) {
    return { get value() { return obj[key]; }, set value(v) { obj[key] = v; } };
  }

  // ------------------------------------------------------------------
  // Boot
  // ------------------------------------------------------------------

  (async function init() {
    await loadPrefs();
    wire();
    await refreshTab();
    await refreshBackendStatus();
    await pollPendingSelection();

    // Re-check status when the panel becomes visible again (worker may have
    // gone idle, server may have started since).
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && !state.busy) refreshBackendStatus();
    });
  })();
})();
