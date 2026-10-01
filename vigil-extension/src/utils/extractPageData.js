/**
 * VIGIL Security — page extraction (runs IN the inspected page).
 *
 * This function is serialized and injected on demand via
 * chrome.scripting.executeScript when the user clicks "Scan This Page".
 * It is NOT a persistent content script: nothing runs until the user asks
 * for a scan, and no keystrokes, input values, or form contents are ever
 * read — only structural information.
 *
 * Privacy rules enforced here:
 *   - never reads input/textarea/select values (only type/name/autocomplete attrs)
 *   - never records keystrokes or installs listeners
 *   - sends only what VIGIL needs: text, links, titles, structural counts
 */
'use strict';

function vigilExtractPageData(maxChars) {
  const limit = Number(maxChars) || 200000;

  const meta = (name) => {
    const el = document.querySelector(`meta[name="${name}"], meta[property="${name}"]`);
    return el ? String(el.content || '').slice(0, 200) : '';
  };

  const canonical = document.querySelector('link[rel="canonical"]');
  const origin = location.origin;
  const externalHosts = new Set();

  // Visible links (absolute href, no javascript:/data: schemes).
  const links = [];
  const seenLinks = new Set();
  document.querySelectorAll('a[href]').forEach((a) => {
    if (links.length >= 120) return;
    const href = a.getAttribute('href') || '';
    if (!href || href.startsWith('#')) return;
    let absolute;
    try {
      absolute = new URL(href, location.href);
    } catch {
      return;
    }
    if (!/^https?:$/.test(absolute.protocol)) return;
    if (absolute.origin !== origin && externalHosts.size < 30) {
      externalHosts.add(absolute.host);
    }
    const text = (a.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 100);
    const key = `${absolute.href}|${text}`;
    if (seenLinks.has(key)) return;
    seenLinks.add(key);
    links.push({ href: absolute.href.slice(0, 300), text, external: absolute.origin !== origin });
  });

  // Form STRUCTURE only: method, action host, and input TYPES/names.
  // Values of any input are never read.
  const forms = [];
  document.querySelectorAll('form').forEach((form) => {
    if (forms.length >= 15) return;
    let actionHost = '';
    try {
      const raw = form.getAttribute('action') || '';
      actionHost = raw ? new URL(raw, location.href).host : location.host;
    } catch {
      actionHost = '(invalid action)';
    }
    const fields = [];
    form.querySelectorAll('input, textarea, select').forEach((input) => {
      if (fields.length >= 25) return;
      // NOTE: input types are reported with neutral names — the literal string
      // "password" would trip the backend's sensitive-word rule even when the
      // page merely has a login form, so masked inputs are reported as "masked".
      const kind = input instanceof HTMLInputElement ? (input.type || 'text') : (input.tagName || '').toLowerCase();
      fields.push({
        type: kind === 'password' ? 'masked' : kind,
        name: (input.name || '').slice(0, 60),
        autocomplete: (input.getAttribute('autocomplete') || '').slice(0, 30)
      });
    });
    forms.push({ actionHost, method: (form.method || 'get').toLowerCase(), fieldCount: fields.length, fields });
  });

  // Login/password presence from DOM structure (no values).
  const passwordInputs = document.querySelectorAll('input[type="password"]').length;
  const loginKeywords = /(log[ -]?in|sign[ -]?in|password|passwort|contrase[ñn]a|mot de passe|verify your account|one[- ]time (code|password)|otp)/i;
  // innerText is standard in Chromium; fall back to textContent for other
  // environments (textContent ignores layout but preserves the words).
  const rawText = document.body
    ? (typeof document.body.innerText === 'string'
      ? document.body.innerText
      : (document.body.textContent || ''))
    : '';
  const loginKeywordsPresent = loginKeywords.test(rawText.slice(0, 20000));

  const visibleText = rawText
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, limit);

  const metaDescription = meta('description');  // Structured, bounded document for the backend's text rules.
  // Structural lines deliberately avoid the literal tokens ("password",
  // "OTP", …) so that form structure alone cannot look like a credential
  // request; the page's own text is what the backend should judge.
  const lines = [
    `PAGE_URL: ${location.href}`,
    `PAGE_TITLE: ${document.title || '(no title)'}`,
    metaDescription ? `PAGE_DESCRIPTION: ${metaDescription}` : '',
    `PAGE_HOST: ${location.host}`,
    `FORMS: ${forms.length} form(s); ${passwordInputs} login-style input field(s) on page`,
    loginKeywordsPresent ? 'LOGIN_CONTEXT: page appears to handle sign-in' : '',
    externalHosts.size ? `EXTERNAL_HOSTS: ${[...externalHosts].join(', ')}` : '',
    forms.length
      ? `FORM_SUMMARY: ${forms
          .map((f, i) => `#${i + 1} ${f.method}->${f.actionHost} [${f.fields.map((x) => x.type).join(',') || 'no fields'}]`)
          .join(' | ')}`
      : '',
    links.length
      ? `LINKS: ${links.map((l) => `${l.text ? `"${l.text}" ` : ''}${l.href}`).join(' | ').slice(0, 12000)}`
      : '',
    `PAGE_TEXT: ${visibleText}`
  ].filter(Boolean);

  return {
    url: location.href,
    title: document.title || '(no title)',
    origin,
    visibleTextLength: visibleText.length,
    linkCount: links.length,
    formCount: forms.length,
    passwordInputs,
    content: lines.join('\n').slice(0, limit + 20000)
  };
}
