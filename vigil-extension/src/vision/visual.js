/**
 * VIGIL Security — local screenshot structure detection (side panel context).
 *
 * Detects input-box-like dark rectangles on light backgrounds and classifies
 * password-mask vs OTP-style cells — measured geometry only, no guessing.
 * Ported from web/vision.js so /api/vision/analyze receives the same
 * visual.rectangles / visual.fields envelope.
 */
'use strict';

(() => {
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

    const measureBoxHeight = (runStart, runWidth, y) => {
      const midX = runStart + Math.round(runWidth / 2);
      let top = y;
      while (top > 2 && luminance(midX, top - 1) < 160) top -= 1;
      let bottom = y;
      while (bottom < height - 3 && luminance(midX, bottom + 1) < 160) bottom += 1;
      return bottom - top;
    };

    const classifyBox = (rect) => {
      const existing = rectangles.find((candidate) => Math.abs(candidate.x - rect.x) < 8
        && Math.abs(candidate.y - rect.y) < 10
        && Math.abs(candidate.width - rect.width) < 12);
      if (existing) return;

      const inset = Math.max(4, Math.round(rect.height * 0.22));
      const left = rect.x + inset;
      const right = rect.x + rect.width - inset;
      const top = rect.y + inset;
      const bottom = rect.y + rect.height - inset;
      if (right - left < 12 || bottom - top < 8) return;

      let transitions = 0;
      let lightPixels = 0;
      let samples = 0;
      let previousLight = null;
      const midY = Math.round((top + bottom) / 2);
      for (let x = left; x < right; x += 1) {
        const light = luminance(x, midY) > 135;
        if (previousLight === null) previousLight = light;
        else if (light !== previousLight) {
          transitions += 1;
          previousLight = light;
        }
        if (light) lightPixels += 1;
        samples += 1;
      }
      const lightRatio = samples ? lightPixels / samples : 0;

      if (transitions >= 10 && lightRatio > 0.25 && lightRatio < 0.75 && rect.width > rect.height * 1.8) {
        fields.passwordFields += 1;
        if (fields.passwordFields <= 3) rectangles.push({ ...rect, label: 'password' });
        return;
      }
      const aspect = rect.width / rect.height;
      if (aspect > 0.45 && aspect < 2.2 && rect.width < Math.round(width * 0.22) && lightRatio > 0.55 && rect.height < 80) {
        fields.otpLikeFields += 1;
        if (fields.otpLikeFields <= 6) rectangles.push({ ...rect, label: 'otp' });
      }
    };

    for (let y = 8; y < height - 8; y += 2) {
      let x = 4;
      while (x < width - 4) {
        if (luminance(x, y) < 130) {
          const runStart = x;
          while (x < width - 4 && luminance(x, y) < 160) x += 1;
          const runWidth = x - runStart;
          if (runWidth >= minRunWidth && runWidth <= maxRunWidth
            && luminance(runStart - 3, y) > 165 && luminance(x + 3, y) > 165) {
            const runHeight = measureBoxHeight(runStart, runWidth, y);
            if (runHeight >= 16 && runHeight <= 90) {
              classifyBox({ x: runStart, y: y - Math.round(runHeight / 2), width: runWidth, height: runHeight });
            }
          }
        } else {
          x += 1;
        }
      }
    }

    return { rectangles, fields };
  }

  self.VigilVisual = { detectVisualStructures };
})();
