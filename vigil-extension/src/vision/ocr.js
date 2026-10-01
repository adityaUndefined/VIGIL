/**
 * VIGIL Security — local OCR pipeline (runs in the SIDE PANEL page context).
 *
 * The service worker has no DOM/canvas, so all image work happens here:
 *   dataURL → canvas preprocessing → Tesseract.js OCR (local WASM)
 *   → word grouping → region list with bounding boxes.
 *
 * This mirrors web/vision.js so the extension posts EXACTLY the payload
 * /api/vision/analyze expects: {image, ocr:{regions, meanConfidence,
 * lowConfidence, degraded}, qr, visual}. No image bytes leave the device —
 * only derived text regions and geometry are posted.
 */
'use strict';

(() => {
  const MAX_OCR_PIXELS = 4000000;
  const LOW_CONFIDENCE_THRESHOLD = 60;
  const MAX_REGIONS = 400;

  let workerPromise = null;

  function workerPaths() {
    return {
      workerPath: chrome.runtime.getURL('vendor/tesseract/worker.min.js'),
      corePath: chrome.runtime.getURL('vendor/tesseract-core'),
      langPath: chrome.runtime.getURL('vendor/langdata')
    };
  }

  async function ensureWorker(onProgress) {
    if (!workerPromise) {
      workerPromise = (async () => {
        const worker = await Tesseract.createWorker('eng', 1, {
          ...workerPaths(),
          logger: (message) => {
            if (message && message.status === 'recognizing text' && typeof message.progress === 'number') {
              if (onProgress) onProgress(Math.round(message.progress * 100));
            }
          }
        });
        await worker.setParameters({
          tessedit_pageseg_mode: '3',
          preserve_interword_spaces: '1'
        });
        return worker;
      })().catch((error) => {
        workerPromise = null; // allow a clean retry
        throw error;
      });
    }
    return workerPromise;
  }

  function terminateWorker() {
    if (workerPromise) {
      workerPromise.then((worker) => worker.terminate()).catch(() => {});
      workerPromise = null;
    }
  }

  /** Upscale small shots, cap total pixels — same rules as the web app. */
  function prepareCanvas(source, width, height) {
    const longEdge = Math.max(width, height);
    let scale = 1;
    if (longEdge < 900) scale = Math.min(2, 900 / longEdge);
    if (width * scale * height * scale > MAX_OCR_PIXELS) {
      scale = Math.sqrt(MAX_OCR_PIXELS / (width * height));
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
    const histogram = new Uint32Array(256);
    for (let i = 0; i < data.length; i += 4) {
      const gray = (data[i] * 299 + data[i + 1] * 587 + data[i + 2] * 114) / 1000;
      data[i] = data[i + 1] = data[i + 2] = gray;
      histogram[gray | 0] += 1;
    }
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
      for (let i = lines.length - 1; i >= 0 && i >= lines.length - 4; i -= 1) {
        const line = lines[i];
        const members = line.words;
        const centerMatch = members.some((member) => {
          const center = member.bbox.y + member.bbox.height / 2;
          const wordCenter = word.bbox.y + word.bbox.height / 2;
          return Math.abs(center - wordCenter) <= Math.max(member.bbox.height, word.bbox.height) * 0.45;
        });
        if (centerMatch) {
          members.push(word);
          placed = true;
          break;
        }
      }
      if (!placed) lines.push({ words: [word] });
    }
    const regions = [];
    for (const line of lines) {
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
    return regions
      .filter((region) => !(region.text.length < 3 && region.confidence < 25))
      .slice(0, MAX_REGIONS);
  }

  async function recognizeCanvas(canvas) {
    const worker = await ensureWorker();
    const result = await worker.recognize(canvas, {}, { text: true, blocks: true });
    return wordsFromResult(result.data);
  }

  /**
   * Full OCR pass with adaptive grayscale retry (same policy as web app).
   * onStep(detail) reports progress; onProgress(0-100) reports OCR %.
   */
  async function runOCR(ctx, width, height, scale, hooks = {}) {
    const onStep = hooks.onStep || (() => {});
    const onProgress = hooks.onProgress || (() => {});
    const regions = await ocrPass(ctx.canvas, scale, onProgress);
    let result = regions;
    let degraded = false;

    const quality = (list) => (list.length
      ? list.reduce((sum, region) => sum + region.confidence, 0) / list.length
      : 0);

    if (quality(result) < 70) {
      onStep('second pass (contrast enhanced)');
      const fallback = document.createElement('canvas');
      fallback.width = width;
      fallback.height = height;
      const fallbackCtx = fallback.getContext('2d', { willReadFrequently: true });
      fallbackCtx.drawImage(ctx.canvas, 0, 0);
      toGrayscaleContrast(fallbackCtx, width, height);
      const fallbackWords = await recognizeCanvas(fallback);
      const fallbackRegions = groupWordsIntoLines(fallbackWords, scale);
      if (fallbackRegions.length > result.length || quality(fallbackRegions) > quality(result) + 4) {
        result = fallbackRegions;
      }
      if (quality(result) < LOW_CONFIDENCE_THRESHOLD) degraded = true;
    }

    const meanConfidence = result.length ? quality(result) : 0;
    const lowConfidence = result.length > 0 && (
      meanConfidence < LOW_CONFIDENCE_THRESHOLD
      || result.filter((region) => region.confidence < LOW_CONFIDENCE_THRESHOLD).length >= Math.max(2, result.length * 0.25)
    );
    return {
      regions: result,
      meanConfidence: Math.round(meanConfidence * 10) / 10,
      lowConfidence,
      degraded
    };
  }

  async function ocrPass(canvas, scale, onProgress) {
    const words = await recognizeCanvas(canvas);
    return groupWordsIntoLines(words, scale);
  }

  /** jsQR scan at three scales (destination never opened, decode only). */
  function scanForQRCodes(ctx, width, height, scale) {
    if (typeof jsQR !== 'function') return [];
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

  self.VigilVision = { prepareCanvas, runOCR, scanForQRCodes, terminateWorker };
})();
