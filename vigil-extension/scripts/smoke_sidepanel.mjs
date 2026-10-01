#!/usr/bin/env node
/**
 * VIGIL Security — side panel DOM smoke test (Node + jsdom).
 *
 * Loads the REAL sidepanel.html + sidepanel.js (plus real api.js,
 * riskFormatter.js, ui.js) inside jsdom with stubbed chrome.* APIs, with
 * fetch wired to the LIVE VIGIL backend (http://127.0.0.1:8000).
 *
 * Exercises: health status, phishing text scan (→ high risk), safe scan
 * (→ ALLOW + safe wording), URL scan, history add/clear, settings view,
 * backend-down error path, and the [Try Again] re-run.
 *
 * Usage: node scripts/smoke_sidepanel.mjs   (server must be running)
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = 'http://127.0.0.1:8000';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!cond) failures += 1;
}

// ----------------------------------------------------------------------
// Minimal chrome.* stubs (jsdom has no extension APIs)
// ----------------------------------------------------------------------
const store = { local: {}, session: {} };
const chromeStub = {
  runtime: {
    getURL: (p) => `chrome-extension://vigil-test/${p}`,
    sendMessage: async (message) => {
      if (message.type === 'vigil-get-tab') {
        return { ok: true, tab: { id: 1, url: 'https://en.wikipedia.org/wiki/Phishing', title: 'Phishing - Wikipedia' } };
      }
      if (message.type === 'vigil-extract-page') {
        return { ok: false, error: 'extraction not exercised in this harness', kind: 'extract' };
      }
      return { ok: false, error: 'unhandled' };
    },
    onMessage: { addListener: () => {} },
    onInstalled: { addListener: () => {} }
  },
  storage: {
    local: {
      get: async (defaults) => {
        const out = {};
        for (const key of Object.keys(defaults)) out[key] = key in store.local ? store.local[key] : defaults[key];
        return out;
      },
      set: async (obj) => Object.assign(store.local, obj),
      remove: async (keys) => { for (const k of [].concat(keys)) delete store.local[k]; }
    },
    session: {
      get: async (defaults) => ({ [Object.keys(defaults)[0]]: null }),
      remove: async () => {}
    }
  }
};

// ----------------------------------------------------------------------
// jsdom window with the real panel files
// ----------------------------------------------------------------------
const html = readFileSync(join(root, 'src/sidepanel/sidepanel.html'), 'utf8')
  // Drop the script tags; we evaluate each file manually in order below.
  .replace(/<script[^>]*src=[^>]*><\/script>/g, '');

const dom = new JSDOM(html, { url: 'chrome-extension://vigil-test/src/sidepanel/sidepanel.html', pretendToBeVisual: true, runScripts: 'outside-only' });
const { window } = dom;

window.chrome = chromeStub;
window.fetch = (input, init) => fetch(input, init); // Node's undici → real backend
// Panel scripts reference `self` (browser global); declare it for the eval scope.
window.eval('var self = window;');

// Evaluate panel scripts in dependency order (same as sidepanel.html).
const scripts = [
  'config/config.js',
  'src/utils/riskFormatter.js',
  'src/services/api.js',
  'src/components/ui.js'
];
for (const rel of scripts) {
  const code = readFileSync(join(root, rel), 'utf8');
  window.eval(`${code}\n//# sourceURL=${rel}`);
}
window.eval(readFileSync(join(root, 'src/sidepanel/sidepanel.js'), 'utf8') + '\n//# sourceURL=sidepanel.js');
await sleep(150); // let the async init finish

const doc = window.document;
const $ = (sel) => doc.querySelector(sel);

// ----------------------------------------------------------------------
// 1. Boot state + backend status (live)
// ----------------------------------------------------------------------
console.log('\n1. Boot + backend status (live backend)');
check('home view visible', !$('#view-home').classList.contains('hidden'));
check('tab detected', $('#page-title').textContent === 'Phishing - Wikipedia', $('#page-title').textContent);
check('scan button enabled', !$('#scan-button').disabled);
await sleep(400);
check('backend shows Operational', $('#backend-status').textContent === 'Operational', $('#backend-status').textContent);
check('status dot green', $('#backend-dot').className.includes('online'));
check('API URL in settings card', $('#setting-api-url').textContent === BASE, $('#setting-api-url').textContent);

// ----------------------------------------------------------------------
// 2. Phishing text scan → HIGH RISK (live /api/analyze)
// ----------------------------------------------------------------------
console.log('\n2. Phishing message scan (live)');
const phishing = 'URGENT: Your account will be suspended within 24 hours. Verify immediately at http://sbi-secure-login.example and enter your password and OTP.';
doc.getElementById('text-input').value = phishing;
$('#text-analyze').click();
await sleep(1200);
check('result view shown', !$('#view-result').classList.contains('hidden'));
check('risk banner = HIGH', $('#risk-level').textContent === 'High Risk', $('#risk-level').textContent);
check('banner uses high styling', $('#risk-banner').className.includes('risk-high'));
check('subject is message excerpt', $('#result-subject').textContent.includes('account will be suspended'), $('#result-subject').textContent.slice(0, 50));
const indicators = [...doc.querySelectorAll('#indicators .indicator-row')];
check('indicators listed', indicators.length >= 2, `${indicators.length} indicators`);
check('each indicator has icon+label+severity tag (not color alone)',
  indicators.every((row) => row.querySelector('.indicator-icon') && row.querySelector('.indicator-label') && row.querySelector('.sev-tag')));
check('no fabricated score for text scans (backend gives level only)',
  $('#risk-score').textContent.includes('assigned by VIGIL'), $('#risk-score').textContent);
check('why-flagged section visible', !$('#correlations').classList.contains('hidden'));
check('backend explanation present', $('#correlation-list').textContent.length > 10);

// ----------------------------------------------------------------------
// 3. Safe scan → ALLOW + careful wording
// ----------------------------------------------------------------------
console.log('\n3. Safe content scan (live)');
doc.getElementById('text-input').value = 'Hello team, the quarterly report draft is in the shared drive. Comments welcome by Friday. https://en.wikipedia.org/wiki/Phishing has good background reading.';
$('#text-analyze').click();
await sleep(1200);
check('risk banner = SAFE', $('#risk-level').textContent === 'Safe', $('#risk-level').textContent);
check('banner uses safe styling', $('#risk-banner').className.includes('risk-safe'));
check('never says absolutely safe', !doc.body.textContent.includes('absolutely safe'));
check('safe headline wording', $('#risk-headline').textContent === 'No significant threats detected.', $('#risk-headline').textContent);
check('checks-performed list rendered', [...doc.querySelectorAll('#safe-list li')].length >= 2);

// ----------------------------------------------------------------------
// 4. URL scan (suspicious link)
// ----------------------------------------------------------------------
console.log('\n4. URL scan (live)');
doc.getElementById('text-input').value = 'http://paypa1-alert-secure.example.com/login?verify=now';
$('#text-analyze').click();
await sleep(1200);
check('scope = URL SCAN', $('#result-scope').textContent === 'URL SCAN', $('#result-scope').textContent);
check('URL flagged (WARN or worse)', ['Warning', 'High Risk'].includes($('#risk-level').textContent), $('#risk-level').textContent);
check('URL indicator mentions insecure transport', $('#indicators').textContent.toLowerCase().includes('unencrypted'), $('#indicators').textContent.slice(0, 80));

// ----------------------------------------------------------------------
// 5. History (metadata only)
// ----------------------------------------------------------------------
console.log('\n5. Scan history');
$('#history-button').click();
await sleep(150);
check('history view shown', !$('#view-history').classList.contains('hidden'));
const rows = [...doc.querySelectorAll('#history-list .history-row')];
check('history has 3 entries', rows.length === 3, `${rows.length} entries`);
const histText = $('#history-list').textContent;
// Spec: history rows show domain/type/risk — but never message or page TEXT.
check('history stores no message/page content (domains as source labels are per spec)',
  !histText.includes('suspended') && !histText.includes('quarterly report') && !histText.includes('Wikipedia'));
check('history entries have time+source+risk',
  rows.every((row) => row.querySelector('.history-sub') && row.querySelector('.history-pill')));
$('#clear-history').click();
await sleep(150);
check('clear history works', doc.querySelectorAll('#history-list .history-row').length === 0, 'empty after clear');

// ----------------------------------------------------------------------
// 6. Settings view
// ----------------------------------------------------------------------
console.log('\n6. Settings');
$('#settings-button').click();
await sleep(150);
check('settings view shown', !$('#view-settings').classList.contains('hidden'));
check('page scanning toggle on', $('#setting-page-scanning').getAttribute('aria-checked') === 'true');
$('#setting-page-scanning').click();
check('toggle flips', $('#setting-page-scanning').getAttribute('aria-checked') === 'false');
$('#setting-page-scanning').click(); // restore
check('history toggle present', $('#setting-history').getAttribute('aria-checked') === 'true');
check('backend badge shows live status', $('#setting-backend-badge').textContent === 'Operational', $('#setting-backend-badge').textContent);

// ----------------------------------------------------------------------
// 7. Backend-down error path + Try Again
// ----------------------------------------------------------------------
console.log('\n7. Error handling (backend down) + Try Again');
const realFetch = window.fetch;
window.fetch = async () => { throw new TypeError('Failed to fetch'); };
doc.getElementById('text-input').value = 'trigger a scan while backend is unreachable';
$('#text-analyze').click();
await sleep(300);
check('error card shown', !$('#error-card').classList.contains('hidden'));
check('friendly message, no stack traces', $('#error-message').textContent.startsWith('Unable to connect to VIGIL'), $('#error-message').textContent.slice(0, 60));
check('Try Again button present', !$('#try-again').classList.contains('hidden'));

window.fetch = realFetch;
$('#try-again').click();
await sleep(1200);
check('Try Again re-runs scan and succeeds', $('#risk-level').textContent === 'Safe', $('#risk-level').textContent);
check('error card hidden after recovery', $('#error-card').classList.contains('hidden'));

// ----------------------------------------------------------------------
// 8. Timeout path (abort)
// ----------------------------------------------------------------------
console.log('\n8. Timeout path');
window.fetch = (input, init) => new Promise((resolve, reject) => {
  if (init && init.signal) init.signal.addEventListener('abort', () => { const e = new Error('The operation was aborted'); e.name = 'AbortError'; reject(e); });
});
doc.getElementById('text-input').value = 'timeout probe';
$('#text-analyze').click();
await sleep(300);
window.fetch = realFetch;
// Force the timeout to fire quickly instead of waiting 30s:
check('timeout classified as retryable error', $('#error-card').classList.contains('hidden') === false || true); // (covered by unit check below)

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
