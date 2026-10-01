/**
 * VIGIL Security — API abstraction layer.
 *
 * Every backend call in the extension goes through this file. No other module
 * calls fetch() directly. The backend (VIGIL's app.py, or the equivalent
 * serverless functions) remains the only source of analysis truth: the
 * extension implements NO detection rules of its own.
 *
 * Endpoint contracts (verified against app.py / vision_engine.py):
 *   POST /api/analyze   {content}            → {decision, risk, evidence[], explanation, analysis_id, local_model}
 *   GET  /api/health                         → {ok, app}
 *   POST /api/vision/analyze {image, ocr, qr, visual}
 *                                             → {decision, risk:{score,level,color,contributions}, indicators, ...}
 *
 * Scan history is stored as METADATA ONLY via chrome.storage (time, source,
 * risk level, score, decision) — never page text or user content.
 */
'use strict';

(() => {
  const CONFIG = (self.VIGIL_CONFIG && self.VIGIL_CONFIG) || {
    API_BASE_URL: 'http://127.0.0.1:8000',
    REQUEST_TIMEOUT_MS: 30000,
    HISTORY_LIMIT: 40
  };
  const BASE = (CONFIG.API_BASE_URL || '').replace(/\/+$/, '');

  const ErrorKind = Object.freeze({
    NETWORK: 'network',
    TIMEOUT: 'timeout',
    SERVER: 'server',
    INVALID: 'invalid'
  });

  class VigilApiError extends Error {
    constructor(kind, userMessage, detail) {
      super(userMessage);
      this.name = 'VigilApiError';
      this.kind = kind;
      this.detail = detail || '';
    }
  }

  /** Map low-level failures to the friendly strings the UI shows. */
  function classifyError(error) {
    if (error instanceof VigilApiError) return error;
    const message = String((error && error.message) || error || '');
    if (error && error.name === 'AbortError') {
      return new VigilApiError(
        ErrorKind.TIMEOUT,
        'Analysis timed out. The VIGIL service took too long to respond. Please try again.',
        message
      );
    }
    if (/failed to fetch|networkerror|load failed|err_(connection|internet|name)/i.test(message)) {
      return new VigilApiError(
        ErrorKind.NETWORK,
        `Unable to connect to VIGIL at ${BASE}. The analysis service may be offline. Please try again.`,
        message
      );
    }
    return new VigilApiError(ErrorKind.INVALID, 'VIGIL could not complete the analysis. Please try again.', message);
  }

  /** fetch() with timeout + JSON contract enforcement. Internal use only. */
  async function request(path, { method = 'GET', body, timeoutMs = CONFIG.REQUEST_TIMEOUT_MS } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetch(`${BASE}${path}`, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      clearTimeout(timer);
    }
    let data = null;
    try {
      data = await response.json();
    } catch {
      data = null; // non-JSON body (proxy error page, empty 502, …)
    }
    if (!response.ok) {
      const serverMessage = data && typeof data.error === 'string' ? data.error : '';
      if (response.status >= 500) {
        throw new VigilApiError(
          ErrorKind.SERVER,
          'VIGIL analysis service is currently unavailable. Please try again shortly.',
          `HTTP ${response.status} ${serverMessage}`
        );
      }
      throw new VigilApiError(
        ErrorKind.INVALID,
        serverMessage || 'VIGIL could not analyze the content you provided. Please try again.',
        `HTTP ${response.status} ${serverMessage}`
      );
    }
    if (!data || typeof data !== 'object') {
      throw new VigilApiError(
        ErrorKind.INVALID,
        'VIGIL returned an unexpected response. Please try again.',
        'Response body was not a JSON object'
      );
    }
    return data;
  }

  // ------------------------------------------------------------------
  // Analysis endpoints (user-initiated only — nothing here runs on a timer)
  // ------------------------------------------------------------------

  /**
   * Analyze free text (a message, page text, or a full URL string).
   * The backend treats the content as text; URL scanning on the web app is
   * simply the URL string posted as content.
   */
  async function analyzeText(content) {
    if (typeof content !== 'string' || !content.trim()) {
      throw new VigilApiError(ErrorKind.INVALID, 'There is no content to analyze.');
    }
    const data = await request('/api/analyze', { method: 'POST', body: { content } });
    if (typeof data.decision !== 'string' || !Array.isArray(data.evidence)) {
      throw new VigilApiError(
        ErrorKind.INVALID,
        'VIGIL returned an unexpected analysis result. Please try again.',
        'Missing decision/evidence in /api/analyze response'
      );
    }
    return data;
  }

  /**
   * Poll a running analysis job (optional local-model review). Mirrors the
   * web app: the rules verdict is shown immediately; when the background
   * model finishes, its verified findings are merged into the result.
   * Resolves with the completed result, or null if it never completes in
   * time (the rules verdict stays authoritative in that case).
   */
  async function pollAnalysis(analysisId, { intervalMs = 500, timeoutMs = 8000, isCancelled = () => false } = {}) {
    if (typeof analysisId !== 'string' || !/^[a-f0-9]{32}$/.test(analysisId)) return null;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline && !isCancelled()) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      if (isCancelled()) return null;
      try {
        // eslint-disable-next-line no-await-in-loop
        const job = await request(`/api/analysis/${analysisId}`, { timeoutMs: 4000 });
        if (job && job.status === 'complete' && job.result) return job.result;
        // status 'pending' → keep polling until the deadline
      } catch {
        return null; // job expired or network blip — rules verdict stands
      }
    }
    return null;
  }

  /** Analyze a URL string via the existing text-analysis endpoint. */
  async function analyzeURL(url) {
    return analyzeText(url);
  }

  /** Analyze a composed page document (used by "Scan This Page"). */
  async function analyzePage(pageData) {
    return analyzeText(pageData.content);
  }

  /**
   * Analyze a screenshot for VIGIL Vision.
   * `visionPayload` is the client-built envelope:
   *   { image: {width, height, sizeBytes, type}, ocr, qr, visual }
   * built by vision/ocr.js + vision/visual.js (local, in the side panel —
   * no image bytes ever leave the device; only derived OCR text/geometry).
   */
  async function analyzeScreenshot(visionPayload) {
    const data = await request('/api/vision/analyze', { method: 'POST', body: visionPayload });
    if (!data.risk || typeof data.risk.level !== 'string' || !Array.isArray(data.indicators)) {
      throw new VigilApiError(
        ErrorKind.INVALID,
        'VIGIL Vision returned an unexpected result. Please try again.',
        'Missing risk/indicators in vision response'
      );
    }
    return data;
  }

  /** Liveness probe used by Settings → Backend status. */
  async function checkHealth(timeoutMs = 6000) {
    try {
      const data = await request('/api/health', { timeoutMs });
      return { online: data && data.ok === true, raw: data };
    } catch {
      return { online: false, raw: null };
    }
  }

  // ------------------------------------------------------------------
  // Scan history — local, metadata-only
  // ------------------------------------------------------------------

  async function getScanHistory() {
    const store = await chrome.storage.local.get({ vigilHistory: [] });
    return Array.isArray(store.vigilHistory) ? store.vigilHistory : [];
  }

  /**
   * Record a completed scan. `entry` carries METADATA ONLY:
   * { source, label, decision, riskLevel, riskScore, kind }.
   * No page text, URLs beyond the hostname, message content, or OCR text is
   * ever written here.
   */
  async function addScanHistory(entry) {
    const allowed = ['source', 'label', 'decision', 'riskLevel', 'riskScore', 'kind'];
    const clean = {};
    for (const key of allowed) {
      if (entry[key] !== undefined) clean[key] = entry[key];
    }
    clean.at = Date.now();
    const history = await getScanHistory();
    history.unshift(clean);
    const trimmed = history.slice(0, CONFIG.HISTORY_LIMIT);
    await chrome.storage.local.set({ vigilHistory: trimmed });
    return trimmed;
  }

  async function clearScanHistory() {
    await chrome.storage.local.remove('vigilHistory');
  }

  /**
   * Update the most recent entry for this kind+source (created <15s ago) in
   * place instead of adding a duplicate — used when the backend's background
   * model review refines a scan that was already recorded.
   */
  async function updateRecentHistory(entry) {
    const history = await getScanHistory();
    const index = history.findIndex((item) => item.kind === entry.kind
      && item.source === entry.source
      && Date.now() - item.at < 15000);
    if (index === -1) {
      return addScanHistory(entry);
    }
    history[index] = { ...history[index], decision: entry.decision, riskLevel: entry.riskLevel, riskScore: entry.riskScore };
    await chrome.storage.local.set({ vigilHistory: history });
    return history;
  }

  self.VigilAPI = {
    ErrorKind,
    VigilApiError,
    classifyError,
    analyzeText,
    pollAnalysis,
    analyzeURL,
    analyzePage,
    analyzeScreenshot,
    checkHealth,
    getScanHistory,
    addScanHistory,
    updateRecentHistory,
    clearScanHistory,
    apiBase: BASE
  };
})();
