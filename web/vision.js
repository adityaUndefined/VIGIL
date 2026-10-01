/* VIGIL Vision — screenshot threat analysis.
 *
 * Pipeline (this file owns the browser half):
 *   upload → validation → preprocessing → OCR (Tesseract.js, local WASM)
 *   → QR decode (jsQR, local) → visual structure detection (measured)
 *   → POST /api/vision/analyze → server correlation + VIGIL risk engine
 *   → editable extracted text + report with per-indicator details.
 *
 * Vision is not "OCR and paste into the Message tab": every text finding keeps
 * its location on the original screenshot, and the report lists each detected
 * indicator with its evidence and risk contribution (Details button).
 *
 * The browser never decides risk. All detection, correlation, and scoring are
 * server-side (vision_engine.py) so Vision reuses VIGIL's existing rules.
 * Nothing in this file logs screenshot contents.
 */
(() => {
  'use strict';

  if (!document.querySelector('#vision-panel')) return; // Vision UI not present

  // ------------------------------------------------------------------
  // Constants
  // ------------------------------------------------------------------
  const ALLOWED_MIME = {
    'image/png': 'PNG', 'image/jpg': 'JPG', 'image/jpeg': 'JPG', 'image/webp': 'WEBP'
  };
  const ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'webp'];
  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const MIN_DIMENSION = 50;
  const MAX_DIMENSION = 5000;
  const MAX_OCR_PIXELS = 4_000_000;
  const TARGET_OCR_LONG_EDGE = 1700;
  const LOW_CONFIDENCE_THRESHOLD = 60;

  const PROCESS_STEPS = [
    { key: 'receive', label: 'Image received' },
    { key: 'preprocess', label: 'Preparing image for analysis' },
    { key: 'ocr', label: 'Extracting text' },
    { key: 'visual', label: 'Detecting visual indicators' },
    { key: 'urls', label: 'Analyzing URLs' },
    { key: 'correlate', label: 'Correlating evidence' },
    { key: 'report', label: 'Preparing security report' }
  ];

  // ------------------------------------------------------------------
  // Elements
  // ------------------------------------------------------------------
  const $ = (selector) => document.querySelector(selector);
  const modeButton = $('#mode-vision');
  const visionPanel = $('#vision-panel');
  const textPanels = [
    $('#message-panel'), $('#url-panel'), $('#html-panel'),
    $('#text-input-footer'), $('#text-input-actions')
  ];
  const dropzone = $('#vision-dropzone');
  const fileInput = $('#vision-file-input');
  const browseButton = $('#vision-browse');
  const demoButton = $('#vision-demo');
  const demoNote = $('#vision-demo-note');
  const errorBox = $('#vision-error');
  const emptyState = $('#empty-state');
  const statusBox = $('#vision-status');
  const stepsList = $('#vision-steps');
  const resultBox = $('#vision-result');
  const textInputPanels = [$('#result'), $('#review-form')];

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------
  const state = {
    busy: false,
    generation: 0,
    demoIndex: 0,
    isDemo: false,
    demoName: '',
    originalExtractedText: '',
    worker: null,
    workerReady: false
  };

  // ------------------------------------------------------------------
  // Small helpers
  // ------------------------------------------------------------------
  function show(element) { element.classList.remove('hidden'); }
  function hide(element) { element.classList.add('hidden'); }

  function visionError(message) {
    errorBox.textContent = message;
    show(errorBox);
    hide(statusBox);
  }
  function clearError() { errorBox.textContent = ''; hide(errorBox); }

  function setVisionVisibility(visible) {
    visionPanel.hidden = !visible;
    textPanels.forEach((panel) => { if (panel) panel.hidden = visible; });
    if (visible) {
      hide(emptyState);
      hide($('#result'));
      hide(resultBox);
      hide(statusBox);
      clearError();
    } else {
      hide(resultBox);
      hide(statusBox);
      clearError();
    }
  }

  function restoreMessageMode() {
    // app.js still considers 'message' the active mode (it ignores 'vision'),
    // so its setMode() early-returns. Restore the message-mode UI here.
    document.querySelectorAll('[data-mode]').forEach((button) => {
      const selected = button.dataset.mode === 'message';
      button.classList.toggle('active', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    document.querySelectorAll('[data-input-panel]').forEach((panel) => {
      panel.hidden = panel.dataset.inputPanel !== 'message';
    });
    const messageInput = $('#content-message');
    if (messageInput) messageInput.focus({ preventScroll: true });
  }

  // app.js can call this first when switching text modes, before its own DOM
  // updates — guarantees Vision closes cleanly even if events fire in either
  // order.
  window.visionModeExit = () => {
    if (!visionActive) return;
    visionActive = false;
    state.generation += 1;
  };

  function resetSteps() {
    stepsList.replaceChildren();
    for (const step of PROCESS_STEPS) {
      const li = document.createElement('li');
      li.dataset.step = step.key;
      const dot = document.createElement('span');
      dot.className = 'step-dot';
      dot.setAttribute('aria-hidden', 'true');
      const label = document.createElement('span');
      label.textContent = step.label;
      li.append(dot, label);
      stepsList.append(li);
    }
  }

  function setStep(key, phase, note) {
    const li = stepsList.querySelector(`[data-step="${key}"]`);
    if (!li) return;
    li.classList.remove('running', 'done', 'skipped');
    if (phase) li.classList.add(phase);
    if (note !== undefined) {
      let label = li.querySelector('span:last-child');
      label.textContent = PROCESS_STEPS.find((s) => s.key === key).label + (note ? ` — ${note}` : '');
    }
  }

  function showStatus() {
    resetSteps();
    show(statusBox);
    hide(resultBox);
    hide(emptyState);
  }

  // ------------------------------------------------------------------
  // Mode wiring (coexists with app.js, which ignores the vision mode)
  // ------------------------------------------------------------------
  let visionActive = false;

  function enterVision() {
    visionActive = true;
    modeButton.classList.add('active');
    modeButton.setAttribute('aria-pressed', 'true');
    document.querySelectorAll('[data-mode]').forEach((button) => {
      if (button !== modeButton) {
        button.classList.remove('active');
        button.setAttribute('aria-pressed', 'false');
      }
    });
    document.querySelectorAll('[data-input-panel]').forEach((panel) => {
      if (panel !== visionPanel) panel.hidden = true;
    });
    setVisionVisibility(true);
  }

  modeButton.addEventListener('click', () => {
    if (state.busy) return;
    enterVision();
  });

  // app.js calls this when the topbar Scanner link is used: it leads directly
  // into VIGIL Vision. Idempotent, so repeated clicks stay on Vision.
  window.visionModeEnter = () => {
    if (visionActive) return;
    enterVision();
  };

  function leaveVision(targetMode) {
    if (!visionActive) return;
    visionActive = false;
    state.generation += 1; // cancel any in-flight work rendering
    visionPanel.hidden = true;
    hide(resultBox);
    hide(statusBox);
    clearError();
    // Text-mode footer/actions were hidden when Vision opened (old single-page
    // layout only — the multi-page scanner has neither element).
    const textFooter = $('#text-input-footer');
    const textActions = $('#text-input-actions');
    if (textFooter) textFooter.hidden = false;
    if (textActions) textActions.hidden = false;
    if (window.clearResult) window.clearResult(); // app.js: resets result/empty state
    else { hide($('#result')); show(emptyState); }
    if (targetMode === 'message') restoreMessageMode();
  }
  [['mode-message', 'message'], ['mode-url', 'url'], ['mode-html', 'html']].forEach(([id, mode]) => {
    const button = document.querySelector(`#${id}`);
    if (button) button.addEventListener('click', () => leaveVision(mode));
  });

  // Topbar "VIGIL Vision" link and #vision deep link: open Vision mode and
  // land on the workbench (mirrors app.js's #scanner anchor behavior).
  const workbench = $('#scanner');
  function openVisionFromLink() {
    modeButton.click(); // reuses the mode handler, including its busy guard
    if (workbench) workbench.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  const topbarVisionLink = document.querySelector('[data-vision-link]');
  if (topbarVisionLink) {
    topbarVisionLink.addEventListener('click', (event) => {
      event.preventDefault(); // there is no #vision element; the mode opens instead
      openVisionFromLink();
    });
  }
  window.addEventListener('hashchange', () => {
    if (location.hash === '#vision') openVisionFromLink();
  });
  if (location.hash === '#vision') openVisionFromLink();

  // ------------------------------------------------------------------
  // Upload interactions
  // ------------------------------------------------------------------
  dropzone.addEventListener('click', (event) => {
    if (event.target === browseButton) return;
    if (!state.busy) fileInput.click();
  });
  dropzone.addEventListener('keydown', (event) => {
    if ((event.key === 'Enter' || event.key === ' ') && !state.busy) {
      event.preventDefault();
      fileInput.click();
    }
  });
  browseButton.addEventListener('click', (event) => {
    event.stopPropagation();
    if (!state.busy) fileInput.click();
  });
  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    if (file) handleFile(file);
    fileInput.value = '';
  });

  ['dragenter', 'dragover'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzone.classList.add('is-dragover');
    });
  });
  ['dragleave', 'drop'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzone.classList.remove('is-dragover');
    });
  });
  dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file && !state.busy) handleFile(file);
  });
  // Never let a stray drop navigate the page away.
  window.addEventListener('dragover', (event) => event.preventDefault());
  window.addEventListener('drop', (event) => event.preventDefault());

  // ------------------------------------------------------------------
  // Validation
  // ------------------------------------------------------------------
  function validateFile(file) {
    const mime = (file.type || '').toLowerCase();
    const name = (file.name || '').toLowerCase();
    const extension = name.includes('.') ? name.split('.').pop() : '';
    const mimeOk = Object.prototype.hasOwnProperty.call(ALLOWED_MIME, mime);
    const extOk = ALLOWED_EXTENSIONS.includes(extension);
    if (!mimeOk && !extOk) {
      return { ok: false, error: 'Unsupported file type. Please upload a PNG, JPG, JPEG, or WEBP screenshot.' };
    }
    if (file.size === 0) {
      return { ok: false, error: 'This file appears to be empty. Please choose a valid screenshot.' };
    }
    if (file.size > MAX_FILE_BYTES) {
      return { ok: false, error: 'This image is larger than 10 MB. Please upload a smaller screenshot.' };
    }
    return { ok: true };
  }

  async function decodeImage(file) {
    try {
      if (window.createImageBitmap) {
        const bitmap = await createImageBitmap(file);
        return { width: bitmap.width, height: bitmap.height, source: bitmap, close: () => bitmap.close() };
      }
    } catch {
      throw new Error('This image could not be read. The file may be corrupted or not a real image.');
    }
    // Fallback path for older browsers.
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.onload = () => resolve({ width: image.naturalWidth, height: image.naturalHeight, source: image, close: () => URL.revokeObjectURL(url) });
      image.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error('This image could not be read. The file may be corrupted or not a real image.'));
      };
      image.src = url;
    });
  }

  function checkDimensions(width, height) {
    if (width < MIN_DIMENSION || height < MIN_DIMENSION) {
      return 'This image is too small to analyze (minimum 50 × 50 pixels).';
    }
    if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
      return 'This image is too large to analyze (maximum 5000 × 5000 pixels). Please resize it and try again.';
    }
    return null;
  }

  // ------------------------------------------------------------------
  // Preprocessing + OCR
  // ------------------------------------------------------------------
  function prepareCanvas(source, width, height) {
    const longEdge = Math.max(width, height);
    let scale = 1;
    if (longEdge < 900) scale = Math.min(2, 900 / longEdge);          // upscale small screenshots
    if (width * scale * height * scale > MAX_OCR_PIXELS) {
      scale = Math.sqrt(MAX_OCR_PIXELS / (width * height));            // cap total pixels
    }
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
    return { canvas, ctx, scale: canvas.width / width };
  }

  function toGrayscaleContrast(ctx, width, height) {
    const image = ctx.getImageData(0, 0, width, height);
    const data = image.data;
    // First pass: grayscale + histogram
    const histogram = new Uint32Array(256);
    for (let i = 0; i < data.length; i += 4) {
      const gray = (data[i] * 299 + data[i + 1] * 587 + data[i + 2] * 114) / 1000;
      data[i] = data[i + 1] = data[i + 2] = gray;
      histogram[gray | 0] += 1;
    }
    // Second pass: percentile contrast stretch (robust to outliers)
    const total = width * height;
    const lowCut = total * 0.02;
    const highCut = total * 0.98;
    let cumulative = 0, low = 0, high = 255;
    for (let v = 0; v < 256; v += 1) {
      cumulative += histogram[v];
      if (cumulative <= lowCut) low = v;
      if (cumulative <= highCut) high = v;
    }
    const range = Math.max(1, high - low);
    for (let i = 0; i < data.length; i += 4) {
      let v = ((data[i] - low) / range) * 255;
      v = v < 0 ? 0 : v > 255 ? 255 : v;
      data[i] = data[i + 1] = data[i + 2] = v;
    }
    ctx.putImageData(image, 0, 0);
  }

  async function ensureWorker() {
    if (state.worker && state.workerReady) return state.worker;
    setStep('ocr', 'running', 'loading local OCR engine');
    const logger = (message) => {
      if (message && message.status === 'recognizing text' && typeof message.progress === 'number') {
        setStep('ocr', 'running', `${Math.round(message.progress * 100)}%`);
      }
    };
    state.worker = await Tesseract.createWorker('eng', 1, {
      workerPath: '/vendor/tesseract/worker.min.js',
      corePath: '/vendor/tesseract-core',
      langPath: '/vendor/langdata',
      logger,
      errorHandler: () => { /* surfaced through recognition failures instead */ }
    });
    await state.worker.setParameters({
      tessedit_pageseg_mode: '3',
      preserve_interword_spaces: '1'
    });
    state.workerReady = true;
    return state.worker;
  }

  function wordsFromResult(data) {
    const words = [];
    const pushWord = (word) => {
      if (!word || typeof word.text !== 'string') return;
      const text = word.text.trim();
      if (!text) return;
      const bbox = word.bbox || {};
      words.push({
        text,
        confidence: typeof word.confidence === 'number' ? word.confidence : 0,
        bbox: {
          x: Math.round(bbox.x0 ?? 0), y: Math.round(bbox.y0 ?? 0),
          width: Math.round((bbox.x1 ?? 0) - (bbox.x0 ?? 0)),
          height: Math.round((bbox.y1 ?? 0) - (bbox.y0 ?? 0))
        }
      });
    };
    if (Array.isArray(data.blocks)) {
      for (const block of data.blocks) {
        for (const paragraph of block.paragraphs || []) {
          for (const line of paragraph.lines || []) {
            for (const word of line.words || []) pushWord(word);
          }
        }
      }
    } else if (Array.isArray(data.words)) {
      for (const word of data.words) pushWord(word);
    }
    return words;
  }

  function groupWordsIntoLines(words, scale) {
    const usable = words.filter((word) => word.text.length > 0);
    usable.sort((a, b) => (a.bbox.y - b.bbox.y) || (a.bbox.x - b.bbox.x));
    const lines = [];
    for (const word of usable) {
      let placed = false;
      // Check ALL open lines, not just the last one: tall first letters (a
      // dropped capital) make later words sort above their line's reference.
      for (let i = lines.length - 1; i >= 0 && i >= lines.length - 4; i -= 1) {
        const line = lines[i];
        const members = line.words;
        const verticalCenterMatch = members.some((member) => {
          const center = member.bbox.y + member.bbox.height / 2;
          const wordCenter = word.bbox.y + word.bbox.height / 2;
          return Math.abs(center - wordCenter) <= Math.max(member.bbox.height, word.bbox.height) * 0.45;
        });
        if (verticalCenterMatch) {
          members.push(word);
          placed = true;
          break;
        }
      }
      if (!placed) lines.push({ words: [word] });
    }
    const regions = [];
    for (const line of lines) {
      // Reading order within a line = left-to-right by x.
      line.words.sort((a, b) => a.bbox.x - b.bbox.x);
      const text = line.words.map((word) => word.text).join(' ').trim();
      if (!text) continue;
      const confidences = line.words.map((word) => word.confidence).filter((c) => c > 0);
      const confidence = confidences.length
        ? confidences.reduce((sum, value) => sum + value, 0) / confidences.length
        : 0;
      const x1 = Math.min(...line.words.map((word) => word.bbox.x));
      const y1 = Math.min(...line.words.map((word) => word.bbox.y));
      const x2 = Math.max(...line.words.map((word) => word.bbox.x + word.bbox.width));
      const y2 = Math.max(...line.words.map((word) => word.bbox.y + word.bbox.height));
      regions.push({
        text,
        confidence: Math.round(confidence * 10) / 10,
        bbox: {
          x: Math.round(x1 / scale), y: Math.round(y1 / scale),
          width: Math.round((x2 - x1) / scale), height: Math.round((y2 - y1) / scale)
        }
      });
    }
    // Drop obvious noise: very low confidence single characters.
    return regions.filter((region) => !(region.text.length < 3 && region.confidence < 25));
  }

  async function recognizeCanvas(canvas) {
    const worker = await ensureWorker();
    const result = await worker.recognize(canvas, {}, { text: true, blocks: true });
    return wordsFromResult(result.data);
  }

  async function runOCR(ctx, width, height, scale) {
    setStep('ocr', 'running');
    const words = await recognizeCanvas(ctx.canvas);
    let regions = groupWordsIntoLines(words, scale);
    let degraded = false;

    const quality = (list) => (list.length
      ? list.reduce((sum, region) => sum + region.confidence, 0) / list.length
      : 0);

    // Adaptive second pass: grayscale + contrast stretch, then keep the better
    // result. Only runs when the first pass looks weak or empty.
    if (quality(regions) < 70) {
      const fallback = document.createElement('canvas');
      fallback.width = width;
      fallback.height = height;
      const fallbackCtx = fallback.getContext('2d', { willReadFrequently: true });
      fallbackCtx.drawImage(ctx.canvas, 0, 0);
      toGrayscaleContrast(fallbackCtx, width, height);
      const fallbackWords = await recognizeCanvas(fallback);
      const fallbackRegions = groupWordsIntoLines(fallbackWords, scale);
      if (fallbackRegions.length > regions.length || quality(fallbackRegions) > quality(regions) + 4) {
        regions = fallbackRegions;
      }
      if (quality(regions) < LOW_CONFIDENCE_THRESHOLD) degraded = true;
    }

    const meanConfidence = regions.length ? quality(regions) : 0;
    const lowConfidence = regions.length > 0 && (
      meanConfidence < LOW_CONFIDENCE_THRESHOLD
      || regions.filter((region) => region.confidence < LOW_CONFIDENCE_THRESHOLD).length >= Math.max(2, regions.length * 0.25)
    );
    setStep('ocr', 'done', regions.length
      ? `${regions.length} region${regions.length === 1 ? '' : 's'} · ${Math.round(meanConfidence)}% confidence`
      : 'no readable text');
    return { regions, meanConfidence, lowConfidence, degraded };
  }

  // ------------------------------------------------------------------
  // QR detection (jsQR, local; destination never opened)
  // ------------------------------------------------------------------
  function scanForQRCodes(ctx, width, height, scale) {
    const codes = [];
    const attempts = [
      { w: width, h: height, canvas: ctx.canvas },
      { w: Math.round(width * 0.5), h: Math.round(height * 0.5) },
      { w: Math.round(width * 1.5), h: Math.round(height * 1.5) }
    ];
    for (const attempt of attempts) {
      if (attempt.w < 40 || attempt.h < 40 || attempt.w > 6000 || attempt.h > 6000) continue;
      let source = attempt.canvas;
      if (attempt.w !== width || attempt.h !== height) {
        const temp = document.createElement('canvas');
        temp.width = attempt.w;
        temp.height = attempt.h;
        const tempCtx = temp.getContext('2d', { willReadFrequently: true });
        tempCtx.imageSmoothingEnabled = true;
        tempCtx.drawImage(ctx.canvas, 0, 0, temp.width, temp.height);
        source = temp;
      }
      try {
        const imageData = source.getContext('2d', { willReadFrequently: true }).getImageData(0, 0, source.width, source.height);
        const found = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'attemptBoth' });
        if (found && found.data && !codes.some((code) => code.data === found.data)) {
          let bbox = null;
          if (found.location) {
            const points = [found.location.topLeftCorner, found.location.topRightCorner, found.location.bottomLeftCorner, found.location.bottomRightCorner];
            const xs = points.map((p) => p.x);
            const ys = points.map((p) => p.y);
            const x1 = Math.min(...xs), y1 = Math.min(...ys);
            bbox = {
              x: Math.round(x1 / scale), y: Math.round(y1 / scale),
              width: Math.round((Math.max(...xs) - x1) / scale),
              height: Math.round((Math.max(...ys) - y1) / scale)
            };
          }
          codes.push({ data: found.data, bbox });
        }
      } catch {
        /* a failed decode attempt is non-fatal; other attempts may still run */
      }
      if (codes.length) break;
    }
    return codes;
  }

  // ------------------------------------------------------------------
  // Visual structure detection (measured geometry, no guessing)
  // ------------------------------------------------------------------
  function detectVisualStructures(ctx, width, height) {
    const rectangles = [];
    const fields = { passwordFields: 0, otpLikeFields: 0 };
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    const luminance = (x, y) => {
      const index = (y * width + x) * 4;
      return (data[index] * 299 + data[index + 1] * 587 + data[index + 2] * 114) / 1000;
    };
    const minRunWidth = Math.max(48, Math.round(width * 0.08));
    const maxRunWidth = Math.round(width * 0.9);

    // Horizontal run detection per sampled row: dark runs bounded by lighter
    // surroundings are candidate input boxes.
    for (let y = 8; y < height - 8; y += 2) {
      let x = 4;
      while (x < width - 4) {
        if (luminance(x, y) < 130) {
          const runStart = x;
          while (x < width - 4 && luminance(x, y) < 160) x += 1;
          const runWidth = x - runStart;
          if (runWidth >= minRunWidth && runWidth <= maxRunWidth && luminance(runStart - 3, y) > 165 && luminance(x + 3, y) > 165) {
            const runHeight = measureBoxHeight(luminance, runStart, runWidth, y, width, height);
            if (runHeight >= 16 && runHeight <= 90) {
              const rect = { x: runStart, y: y - Math.round(runHeight / 2), width: runWidth, height: runHeight };
              classifyBox(rect, rectangles, fields, luminance, width, height);
            }
          }
        } else {
          x += 1;
        }
      }
    }

    function measureBoxHeight(lum, runStart, runWidth, y, w, h) {
      const midX = runStart + Math.round(runWidth / 2);
      let top = y;
      while (top > 2 && lum(midX, top - 1) < 160) top -= 1;
      let bottom = y;
      while (bottom < h - 3 && lum(midX, bottom + 1) < 160) bottom += 1;
      return bottom - top;
    }

    function classifyBox(rect, out, fieldCounts, lum, w, h) {
      // Merge with an existing nearby box (same box seen on multiple rows).
      const existing = out.find((candidate) => Math.abs(candidate.x - rect.x) < 8
        && Math.abs(candidate.y - rect.y) < 10
        && Math.abs(candidate.width - rect.width) < 12);
      if (existing) return;

      const inset = Math.max(4, Math.round(rect.height * 0.22));
      const left = rect.x + inset;
      const right = rect.x + rect.width - inset;
      const top = rect.y + inset;
      const bottom = rect.y + rect.height - inset;
      if (right - left < 12 || bottom - top < 8) return;

      // Sample the interior: light-run statistics.
      let transitions = 0;
      let lightPixels = 0;
      let samples = 0;
      let previousLight = null;
      const midY = Math.round((top + bottom) / 2);
      for (let x = left; x < right; x += 1) {
        const light = lum(x, midY) > 135;
        if (previousLight === null) previousLight = light;
        else if (light !== previousLight) {
          transitions += 1;
          previousLight = light;
        }
        if (light) lightPixels += 1;
        samples += 1;
      }
      const lightRatio = samples ? lightPixels / samples : 0;

      // Password dot-mask: frequent alternation, moderate light coverage.
      if (transitions >= 10 && lightRatio > 0.25 && lightRatio < 0.75 && rect.width > rect.height * 1.8) {
        fieldCounts.passwordFields += 1;
        if (fieldCounts.passwordFields <= 3) out.push({ ...rect, label: 'password' });
        return;
      }
      // OTP/PIN cell: small, near-square, mostly light interior.
      const aspect = rect.width / rect.height;
      if (aspect > 0.45 && aspect < 2.2 && rect.width < Math.round(w * 0.22) && lightRatio > 0.55 && rect.height < 80) {
        fieldCounts.otpLikeFields += 1;
        if (fieldCounts.otpLikeFields <= 6) out.push({ ...rect, label: 'otp' });
      }
    }

    return { rectangles, fields };
  }

  // ------------------------------------------------------------------
  // Indicator details (rendered inline under the indicator)
  // ------------------------------------------------------------------
  let currentResult = null;

  function renderIndicatorDetails(li, indicator) {
    const existing = li.querySelector('.ind-details');
    const open = li.querySelector('.ind-open');
    if (existing) existing.remove();
    if (open && open.dataset.indicatorLabel === String(indicator.label || '')) {
      if (open) open.dataset.indicatorLabel = '';
      return; // second click hides the details
    }
    if (open) open.dataset.indicatorLabel = String(indicator.label || '');
    const details = document.createElement('div');
    details.className = 'ind-details';
    const rows = [
      ['DETECTED', indicator.detected],
      ['SOURCE', indicator.source],
      ['OCR CONFIDENCE', indicator.confidence != null ? `${indicator.confidence}%` : null],
      ['RISK CONTRIBUTION', indicator.riskContribution && indicator.severity !== 'info' && indicator.severity !== 'low'
        ? `+${indicator.riskContribution}`
        : '—'],
      // The server echoes each indicator's actual weight (riskContribution);
      // no client-side copy of the weight table, so it can never go stale.
      ['REASON', indicator.reason, 'ind-details-reason']
    ];
    rows.forEach(([name, value, extraClass]) => {
      const row = document.createElement('p');
      row.className = extraClass ? `ind-details-row ${extraClass}` : 'ind-details-row';
      const label = document.createElement('span');
      label.textContent = name;
      const valueEl = document.createElement('strong');
      valueEl.textContent = value || '—';
      row.append(label, valueEl);
      details.append(row);
    });
    li.append(details);
  }

  // ------------------------------------------------------------------
  // Result rendering
  // ------------------------------------------------------------------
  function renderResult(result, meta) {
    currentResult = result;
    hide(statusBox);
    show(resultBox);
    hide(emptyState);

    // Decision + scenario tag
    const decisionPill = $('#vision-decision');
    decisionPill.textContent = result.decision;
    decisionPill.className = `decision-pill ${result.decision.toLowerCase()}`;
    const scenarioTag = $('#vision-scenario-tag');
    if (meta.isDemo) {
      scenarioTag.textContent = `DEMO SCENARIO · ${meta.demoName}`;
      show(scenarioTag);
    } else {
      hide(scenarioTag);
    }

    // Risk card
    const risk = result.risk;
    const level = $('#vision-risk-level');
    level.textContent = risk.level;
    level.className = `vision-risk-level ${risk.color}`;
    $('#vision-risk-score').textContent = risk.score;
    const fill = $('#vision-risk-bar-fill');
    fill.style.width = '0%';
    requestAnimationFrame(() => {
      fill.style.width = `${risk.score}%`;
      fill.className = risk.color;
    });

    // Uploaded screenshot (full-size view)
    const shotHolder = $('#vision-screenshot-holder');
    shotHolder.replaceChildren();
    const shotCanvas = document.createElement('canvas');
    shotCanvas.width = meta.imageWidth;
    shotCanvas.height = meta.imageHeight;
    shotCanvas.setAttribute('role', 'img');
    shotCanvas.setAttribute('aria-label', 'Uploaded screenshot');
    shotCanvas.getContext('2d').drawImage(meta.imageSource, 0, 0);
    shotHolder.append(shotCanvas);
    $('#vision-ocr-confidence').textContent = result.ocr.regionCount
      ? `${Math.round(result.ocr.meanConfidence)}%`
      : 'none';
    $('#vision-region-count').textContent = String(result.ocr.regionCount);
    const notes = $('#vision-confidence-notes');
    notes.replaceChildren();
    (result.confidenceNotes || []).forEach((note) => {
      const p = document.createElement('p');
      p.textContent = note;
      notes.append(p);
    });

    // Indicators
    const list = $('#vision-indicator-list');
    list.replaceChildren();
    (result.indicators || []).forEach((indicator) => {
      const li = document.createElement('li');
      li.className = `sev-${indicator.severity}`;
      const label = document.createElement('span');
      label.className = 'ind-label';
      label.textContent = indicator.label;
      const detected = document.createElement('span');
      detected.className = 'ind-detected';
      detected.textContent = indicator.detected;
      const chip = document.createElement('span');
      chip.className = 'ind-chip';
      chip.textContent = `${indicator.source} · ${indicator.confidence}%`;
      const open = document.createElement('button');
      open.type = 'button';
      open.className = 'ind-open';
      open.textContent = 'Details';
      open.addEventListener('click', () => renderIndicatorDetails(li, indicator));
      li.append(label, detected, chip, open);
      list.append(li);
    });

    // Correlated evidence groups
    (result.correlated || []).forEach((group) => {
      const li = document.createElement('li');
      li.className = 'sev-medium correlated-group';
      const title = document.createElement('span');
      title.className = 'ind-label';
      title.textContent = `🔗 ${group.title}`;
      const summary = document.createElement('span');
      summary.className = 'ind-detected';
      summary.textContent = group.summary;
      li.append(title, summary);
      list.append(li);
    });

    // Extracted information lists
    fillList('#vision-ex-urls', (result.extracted.urls || []).map((url) => ({
      text: url.url + (url.recovered ? '  (recovered from OCR)' : ''),
      risky: url.risky
    })), 'No URLs detected');
    fillList('#vision-ex-qr', (result.extracted.qrCodes || []).map((qr) => ({ text: qr.data, risky: qr.risky })), 'No QR codes detected');
    const contacts = [...(result.extracted.phones || []).map((phone) => ({ text: phone })), ...(result.extracted.emails || []).map((email) => ({ text: email }))];
    fillList('#vision-ex-contacts', contacts, 'No contact indicators');
    fillList('#vision-ex-brands', (result.extracted.brandReferences || []).map((brand) => ({ text: brand })), 'No brand references');
    fillList('#vision-ex-payments', (result.extracted.paymentIndicators || []).map((payment) => ({ text: payment })), 'No payment indicators');

    // URL security analysis (actual analyzer output)
    const findingsBox = $('#vision-url-findings');
    const findingsList = $('#vision-url-findings-list');
    findingsList.replaceChildren();
    const urlResults = result.urls || [];
    if (urlResults.length) {
      urlResults.forEach((urlResult) => {
        const entry = document.createElement('div');
        const host = document.createElement('p');
        host.className = 'url-host';
        host.textContent = urlResult.host || urlResult.url;
        entry.append(host);
        const meaningful = (urlResult.findings || []).filter((finding) => finding.severity !== 'info');
        if (meaningful.length) {
          meaningful.forEach((finding) => {
            const p = document.createElement('p');
            p.className = `url-finding sev-${finding.severity}`;
            p.textContent = finding.fact;
            entry.append(p);
          });
        } else {
          const p = document.createElement('p');
          p.className = 'url-clean';
          p.textContent = 'No structural warning signs found for this address. This is not a safety guarantee — VIGIL does not visit links.';
          entry.append(p);
        }
        findingsList.append(entry);
      });
      show(findingsBox);
    } else {
      hide(findingsBox);
    }

    // Extracted text editor.
    const textArea = $('#vision-text-input');
    state.originalExtractedText = result.extracted.text || '';
    textArea.value = state.originalExtractedText;
    updateTextState();
    textArea.disabled = false;

    // WHY breakdown — only real contributions
    const why = $('#vision-why');
    why.replaceChildren();
    if (risk.contributions && risk.contributions.length) {
      risk.contributions.forEach((contribution) => {
        const p = document.createElement('p');
        p.style.display = 'flex';
        p.style.justifyContent = 'space-between';
        p.style.gap = '12px';
        const label = document.createElement('span');
        label.textContent = contribution.label;
        const points = document.createElement('strong');
        points.textContent = `+${contribution.points}`;
        p.style.borderLeft = `3px solid ${contribution.color === 'red' ? '#bd473f' : contribution.color === 'orange' ? '#d98f16' : '#5a7fae'}`;
        p.style.paddingLeft = '9px';
        p.append(label, points);
        why.append(p);
      });
    } else {
      const p = document.createElement('p');
      p.className = 'vision-why-empty';
      p.textContent = 'No risk contributions: no high or medium security indicators were detected in this screenshot.';
      why.append(p);
    }

    // Deterministic explanation + actions
    const actions = $('#vision-actions');
    actions.replaceChildren();
    (result.recommendedActions || []).forEach((action) => {
      const li = document.createElement('li');
      li.textContent = action;
      actions.append(li);
    });
  }

  function fillList(selector, items, emptyLabel) {
    const list = $(selector);
    list.replaceChildren();
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'dim';
      li.textContent = emptyLabel;
      list.append(li);
      return;
    }
    items.forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item.text;
      if (item.risky) li.classList.add('risky');
      list.append(li);
    });
  }

  // ------------------------------------------------------------------
  // Extracted text editing + re-run
  // ------------------------------------------------------------------
  function updateTextState() {
    const textArea = $('#vision-text-input');
    const chip = $('#vision-text-state');
    const edited = textArea.value !== state.originalExtractedText;
    chip.classList.toggle('hidden', !edited);
  }
  $('#vision-text-input').addEventListener('input', updateTextState);

  // ------------------------------------------------------------------
  // Restart
  // ------------------------------------------------------------------
  $('#vision-restart').addEventListener('click', () => {
    if (state.busy) return;
    state.isDemo = false;
    state.demoName = '';
    currentResult = null;
    setVisionVisibility(true);
    demoNote.textContent = 'Safe synthetic examples — no real accounts or credentials';
  });

  // ------------------------------------------------------------------
  // Main pipeline
  // ------------------------------------------------------------------
  async function analyzeSource(source, width, height, meta) {
    const generation = ++state.generation;
    state.busy = true;
    state.isDemo = meta.isDemo;
    state.demoName = meta.demoName || '';
    state.imageWidth = width;
    state.imageHeight = height;
    state.imageSource = source;
    showStatus();
    clearError();
    setStep('receive', 'done', `${width} × ${height}`);

    try {
      const { canvas, ctx, scale } = prepareCanvas(source, width, height);

      setStep('preprocess', 'running');
      await nextFrame();
      setStep('preprocess', 'done', scale !== 1 ? `rescaled ×${scale.toFixed(2)}` : 'ready');

      const ocr = await runOCR(ctx, canvas.width, canvas.height, scale);
      if (generation !== state.generation) return;

      setStep('visual', 'running');
      await nextFrame();
      let visual = { rectangles: [], fields: { passwordFields: 0, otpLikeFields: 0 } };
      let qrCodes = [];
      try {
        visual = detectVisualStructures(ctx, canvas.width, canvas.height);
        const scaledRects = visual.rectangles.map((rect) => ({
          x: Math.round(rect.x / scale), y: Math.round(rect.y / scale),
          width: Math.round(rect.width / scale), height: Math.round(rect.height / scale),
          label: rect.label
        }));
        visual.rectangles = scaledRects;
      } catch {
        /* visual detection is best-effort; OCR + rules still apply */
      }
      try {
        if (window.jsQR) qrCodes = scanForQRCodes(ctx, canvas.width, canvas.height, scale);
      } catch {
        /* QR failure is non-fatal */
      }
      const foundVisual = visual.rectangles.length > 0 || qrCodes.length > 0;
      setStep('visual', 'done', foundVisual
        ? `${qrCodes.length ? `${qrCodes.length} QR · ` : ''}${visual.fields.passwordFields ? `${visual.fields.passwordFields} password field${visual.fields.passwordFields === 1 ? '' : 's'} · ` : ''}${visual.fields.otpLikeFields ? `${visual.fields.otpLikeFields} OTP-style · ` : ''}done`.replace(/ · $/, '')
        : 'no QR or input fields found');

      setStep('urls', 'running');
      setStep('correlate', 'running');
      const payload = {
        image: { width, height, sizeBytes: meta.sizeBytes, type: meta.type },
        ocr,
        qr: qrCodes,
        visual: { rectangles: visual.rectangles, fields: visual.fields }
      };
      const response = await fetch('/api/vision/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'VIGIL Vision could not complete this analysis.');
      if (generation !== state.generation) return;
      setStep('urls', 'done');
      setStep('correlate', 'done');
      setStep('report', 'done');

      renderResult(data, {
        isDemo: meta.isDemo,
        demoName: meta.demoName,
        imageWidth: width,
        imageHeight: height,
        imageSource: source
      });
    } catch (error) {
      if (generation !== state.generation) return;
      const message = error && error.message ? error.message : '';
      if (/worker|tesseract|OCR engine/i.test(message)) {
        visionError('The local OCR engine could not start. Please reload the page and try again.');
      } else if (/network|fetch|Failed to fetch/i.test(message)) {
        visionError('VIGIL could not reach its analysis service. Check your connection and try again.');
      } else {
        visionError(message || 'This screenshot could not be analyzed. Please try a different image.');
      }
    } finally {
      if (generation === state.generation) state.busy = false;
    }
  }

  function nextFrame() {
    return new Promise((resolve) => requestAnimationFrame(() => resolve()));
  }

  async function handleFile(file) {
    if (state.busy) return;
    clearError();
    const validation = validateFile(file);
    if (!validation.ok) {
      visionError(validation.error);
      return;
    }
    let decoded = null;
    try {
      decoded = await decodeImage(file);
    } catch (error) {
      visionError(error.message);
      return;
    }
    const dimensionError = checkDimensions(decoded.width, decoded.height);
    if (dimensionError) {
      decoded.close();
      visionError(dimensionError);
      return;
    }
    await analyzeSource(decoded.source, decoded.width, decoded.height, {
      isDemo: false,
      demoName: '',
      sizeBytes: file.size,
      type: file.type || ''
    });
    // Keep the decoded image alive for the result view; close it when replaced.
    if (state.previousDecode && state.previousDecode.close) state.previousDecode.close();
    state.previousDecode = decoded;
  }

  // ------------------------------------------------------------------
  // Demo mode — safe, fully synthetic scenarios (no real infrastructure)
  // ------------------------------------------------------------------
  function buildDemoCanvas(kind) {
    const width = 560;
    const height = 640;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    // Phone-ish frame
    ctx.fillStyle = '#e8e8e4';
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(20, 20, width - 40, height - 40);

    const header = (color, title) => {
      ctx.fillStyle = color;
      ctx.fillRect(20, 20, width - 40, 54);
      ctx.fillStyle = '#ffffff';
      ctx.font = '700 22px sans-serif';
      ctx.textBaseline = 'middle';
      ctx.fillText(title, 36, 47);
    };
    const body = (lines, startY, color, size, weight) => {
      ctx.fillStyle = color || '#222';
      ctx.font = `${weight || 400} ${size || 17}px sans-serif`;
      ctx.textBaseline = 'alphabetic';
      let y = startY;
      for (const line of lines) {
        ctx.fillText(line, 36, y);
        y += Math.round((size || 17) * 1.5);
      }
      return y;
    };
    const drawQR = (text, x, y, size) => {
      try {
        const qr = qrcode(0, 'M');
        qr.addData(text);
        qr.make();
        const moduleCount = qr.getModuleCount();
        const cell = size / moduleCount;
        ctx.fillStyle = '#111';
        for (let row = 0; row < moduleCount; row += 1) {
          for (let col = 0; col < moduleCount; col += 1) {
            if (qr.isDark(row, col)) ctx.fillRect(x + col * cell, y + row * cell, cell + 0.5, cell + 0.5);
          }
        }
        ctx.strokeStyle = '#111';
        ctx.lineWidth = 2;
        ctx.strokeRect(x - 6, y - 6, size + 12, size + 12);
      } catch {
        ctx.fillStyle = '#111';
        ctx.fillRect(x, y, size, size);
      }
    };
    const inputBox = (x, y, w, h, dots) => {
      ctx.strokeStyle = '#8a8a8a';
      ctx.lineWidth = 2;
      ctx.strokeRect(x, y, w, h);
      ctx.fillStyle = '#f2f2f2';
      ctx.fillRect(x + 1, y + 1, w - 2, h - 2);
      if (dots) {
        ctx.fillStyle = '#333';
        const dotCount = Math.floor((w - 24) / 18);
        for (let i = 0; i < dotCount; i += 1) {
          ctx.beginPath();
          ctx.arc(x + 18 + i * 18, y + h / 2, 5, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    };
    const button = (label, x, y, w, h) => {
      ctx.fillStyle = '#1d5b3b';
      ctx.fillRect(x, y, w, h);
      ctx.fillStyle = '#fff';
      ctx.font = '700 16px sans-serif';
      ctx.textBaseline = 'middle';
      const textWidth = ctx.measureText(label).width;
      ctx.fillText(label, x + (w - textWidth) / 2, y + h / 2);
      ctx.textBaseline = 'alphabetic';
    };

    if (kind === 'bank-phish') {
      header('#7a1f1f', 'SBI ALERT');
      body([
        'URGENT: Your SBI account will',
        'be BLOCKED today.',
        '',
        'Complete KYC immediately to',
        'avoid suspension.'
      ], 110, '#111', 18, 600);
      body(['Verify here:'], 240, '#444', 15);
      body(['https://sbi-kyc-alert.example/verify'], 268, '#1a4f9c', 15, 600);
      body(['Enter password & OTP below:'], 316, '#444', 15);
      inputBox(36, 336, 488, 44, true);
      inputBox(36, 396, 488, 44, true);
      button('VERIFY NOW', 36, 460, 488, 48);
      body(['Customer care: +91 80 4000 1234'], 560, '#666', 14);
    } else if (kind === 'delivery-scam') {
      header('#4a4a6a', 'FedEx Delivery');
      body([
        'Your package MH-8837201 is ON',
        'HOLD at our warehouse.',
        '',
        'Pay a redelivery fee of $2.99',
        'within 24 hours or it will be',
        'returned.'
      ], 110, '#111', 18);
      body(['Pay securely:'], 288, '#444', 15);
      body(['https://fedex-redelivery.example/pay'], 316, '#1a4f9c', 15, 600);
      drawQR('https://fedex-redelivery.example/pay?fee=2.99', 200, 356, 160);
      body(['Support: +1 888 555 0199'], 584, '#666', 14);
    } else if (kind === 'fake-login') {
      header('#1d3a5f', 'NetBank Secure');
      body(['Login to continue'], 110, '#111', 20, 700);
      body(['Customer ID'], 150, '#444', 14);
      inputBox(36, 162, 488, 42, false);
      body(['Password'], 224, '#444', 14);
      inputBox(36, 236, 488, 42, true);
      body(['OTP (6 digits)'], 298, '#444', 14);
      inputBox(36, 310, 110, 42, false);
      inputBox(156, 310, 110, 42, false);
      inputBox(276, 310, 110, 42, false);
      button('SIGN IN', 36, 380, 488, 48);
      body(['https://secure-netbank-login.example/signin'], 470, '#1a4f9c', 14, 600);
      body(['Forgot password | Create account'], 520, '#666', 13);
    } else if (kind === 'qr-payment') {
      header('#5f1d5f', 'Payment Request');
      body([
        'Scan to pay ₹4,999.00',
        'immediately to confirm your',
        'order.'
      ], 110, '#111', 19, 600);
      drawQR('upi://pay?pa=demo-pay@vigiltest&pn=Demo&am=4999.00&cu=INR', 180, 210, 200);
      body(['Amount: ₹4,999.00'], 456, '#111', 17, 700);
      body(['Pay now — limited time offer'], 486, '#a33', 15, 600);
      body(['Supported by ExamplePay'], 560, '#666', 14);
    } else {
      header('#1d5b3b', 'Messages');
      body([
        'Hi Mira,',
        '',
        'The project review is at 3 PM',
        'today in Room 204. Please bring',
        'the latest slides.',
        '',
        'Thanks!',
        'Sam'
      ], 110, '#111', 18);
      body(['Delivered · 2:14 PM'], 560, '#888', 13);
    }

    return canvas;
  }

  const DEMO_SCENARIOS = [
    { key: 'bank-phish', name: 'Bank KYC phishing screenshot' },
    { key: 'delivery-scam', name: 'Fake delivery fee message' },
    { key: 'fake-login', name: 'Fake login page' },
    { key: 'qr-payment', name: 'QR payment scam' },
    { key: 'legit-notice', name: 'Legitimate notification' }
  ];

  demoButton.addEventListener('click', async () => {
    if (state.busy) return;
    const scenario = DEMO_SCENARIOS[state.demoIndex % DEMO_SCENARIOS.length];
    state.demoIndex += 1;
    demoNote.textContent = `Loaded: ${scenario.name} (synthetic)`;
    const canvas = buildDemoCanvas(scenario.key);
    await analyzeSource(canvas, canvas.width, canvas.height, {
      isDemo: true,
      demoName: scenario.name.toUpperCase(),
      sizeBytes: 0,
      type: 'image/png'
    });
  });
})();
