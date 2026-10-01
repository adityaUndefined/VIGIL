// test_tab_actions.mjs — verifies the tab-aware action bar on web/scanner.html.
//
// Checks, using the REAL markup plus the REAL app.js and vision.js in jsdom:
//   * every tab (Message / URL / HTML / VIGIL Vision) shows its own primary
//     action inside the single #text-input-actions container,
//   * repeated switching — including through VIGIL Vision, the path that used
//     to leave the button hidden — never hides the action bar or its buttons,
//   * the primary/secondary buttons stay clickable and their handlers fire,
//   * typed input state survives tab switches.
//
// Requires jsdom (dev dependency):  npm run test:ui

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

let JSDOM, VirtualConsole;
try {
  ({ JSDOM, VirtualConsole } = await import('jsdom'));
} catch {
  console.error('SKIP: jsdom is not installed (run: npm i -D jsdom)');
  process.exit(1);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const ok = (condition, message) => {
  console.log(`${condition ? '  ✓' : '  ✗'} ${message}`);
  if (!condition) failures += 1;
};

// An element is visible only if neither visibility mechanism hides it:
// the [hidden] attribute (scanner.html forces display:none for it) and the
// .hidden utility class (Tailwind).
const shown = (el) => !!el && !el.hidden && !el.classList.contains('hidden');

// Expected UI per tab: which input panel is open, which button is primary,
// and what that primary button says.
const TABS = {
  message: { panel: 'message-panel', primary: 'analyze', label: 'Scan content' },
  url: { panel: 'url-panel', primary: 'analyze', label: 'Check URL' },
  html: { panel: 'html-panel', primary: 'analyze', label: 'Scan HTML' },
  vision: { panel: 'vision-panel', primary: 'vision-upload', label: 'Upload screenshot' }
};

const pageErrors = [];

function bootPage() {
  const html = fs.readFileSync(path.join(root, 'web', 'scanner.html'), 'utf8');
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', (error) => pageErrors.push(error));
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'http://localhost/scanner.html',
    pretendToBeVisual: true,
    virtualConsole
  });
  const { window } = dom;

  // app.js fetches /api/* on load; answer with a neutral offline payload.
  window.fetch = async () => ({
    ok: true,
    json: async () => ({
      status: 'offline',
      model: 'none',
      title: 'Offline example',
      description: 'No local model in tests.',
      threat_level: 'LOW'
    })
  });

  // jsdom does not execute external <script src> tags — run the real files.
  for (const file of ['app.js', 'vision.js']) {
    const script = window.document.createElement('script');
    script.textContent = fs.readFileSync(path.join(root, 'web', file), 'utf8');
    window.document.body.append(script);
  }
  return window;
}

function clickTab(window, mode) {
  window.document.querySelector(`[data-mode="${mode}"]`).click();
}

function assertTab(window, mode, context) {
  const doc = window.document;
  const tag = `[${context}] ${mode}`;
  const actions = doc.querySelector('#text-input-actions');
  const expected = TABS[mode];

  ok(shown(actions), `${tag}: action bar visible`);
  ok(
    actions.dataset.actionsFor === mode,
    `${tag}: action bar bound to "${mode}" (got "${actions.dataset.actionsFor}")`
  );

  const tab = doc.querySelector(`[data-mode="${mode}"]`);
  ok(
    tab.classList.contains('active') && tab.getAttribute('aria-pressed') === 'true',
    `${tag}: tab styled active`
  );

  const panels = Object.entries(TABS)
    .map(([m, cfg]) => `${m}:${shown(doc.querySelector(`#${cfg.panel}`)) ? 'open' : 'shut'}`)
    .join(' ');
  const expectedPanels = Object.keys(TABS)
    .map((m) => `${m}:${m === mode ? 'open' : 'shut'}`)
    .join(' ');
  ok(panels === expectedPanels, `${tag}: panels ${panels}`);

  const analyze = doc.querySelector('#analyze');
  const clear = doc.querySelector('#clear-input');
  const upload = doc.querySelector('#vision-upload');
  const isVision = mode === 'vision';
  ok(shown(analyze) === !isVision, `${tag}: Scan/Check button ${isVision ? 'hidden' : 'visible'}`);
  ok(shown(clear) === !isVision, `${tag}: Clear button ${isVision ? 'hidden' : 'visible'}`);
  ok(shown(upload) === isVision, `${tag}: Upload button ${isVision ? 'visible' : 'hidden'}`);

  const primary = doc.querySelector(`#${expected.primary}`);
  ok(shown(primary) && !primary.disabled, `${tag}: primary "#${expected.primary}" visible and enabled`);
  if (!isVision) {
    const label = analyze.querySelector('[data-button-label]').textContent;
    ok(label === expected.label, `${tag}: primary label "${expected.label}" (got "${label}")`);
  } else {
    const label = upload.textContent.trim();
    ok(label.includes(expected.label), `${tag}: primary label "${expected.label}" (got "${label}")`);
  }
}

// ---------------------------------------------------------------- boot + load
console.log('boot: scanner.html + app.js + vision.js');
const window = bootPage();
const doc = window.document;
const actionBar = doc.querySelector('#text-input-actions');

ok(pageErrors.length === 0, `page scripts ran without errors${pageErrors.length ? ` (${pageErrors[0]})` : ''}`);
ok(shown(actionBar), 'initial: action bar visible on Message tab');
assertTab(window, 'message', 'initial');

// ------------------------------------------------- repeated tab switching loop
const ORDER = ['message', 'url', 'html', 'vision'];
for (let cycle = 1; cycle <= 3; cycle += 1) {
  console.log(`cycle ${cycle}: message → url → html → vision`);
  for (const mode of ORDER) {
    clickTab(window, mode);
    assertTab(window, mode, `cycle ${cycle}`);
  }
}

// -------------------------------------------- the originally reported sequence
console.log('regression: Message → URL → HTML → VIGIL Vision → Message');
for (const mode of ['url', 'html', 'vision', 'message']) clickTab(window, mode);
assertTab(window, 'message', 'regression');

// Vision opened FROM the URL tab, then straight back to URL (panel restore).
console.log('regression: URL → VIGIL Vision → URL');
clickTab(window, 'url');
clickTab(window, 'vision');
assertTab(window, 'vision', 'regression url→vision');
clickTab(window, 'url');
assertTab(window, 'url', 'regression url→vision→url');

// --------------------------------------------------------------- input state
console.log('state: typed input survives tab switches');
clickTab(window, 'message');
doc.querySelector('#content-message').value = 'hi there';
for (const mode of ['url', 'html', 'vision', 'message']) clickTab(window, mode);
ok(
  doc.querySelector('#content-message').value === 'hi there',
  'message text preserved after cycling all tabs'
);

// ------------------------------------------------------------- clickability
console.log('clicks: primary/secondary actions still fire');
// Message: empty submit runs app.js validation (no fetch needed).
doc.querySelector('#content-message').value = '';
doc.querySelector('#analyze').click();
const result = doc.querySelector('#result');
ok(
  shown(result) && result.classList.contains('is-error'),
  'click: empty Message submit shows the validation error card'
);

// Secondary action clears the input.
doc.querySelector('#content-message').value = 'hello';
doc.querySelector('#clear-input').click();
ok(doc.querySelector('#content-message').value === '', 'click: Clear empties the input');

// URL: primary submits the form for the active tab.
clickTab(window, 'url');
doc.querySelector('#content-url').value = '';
doc.querySelector('#analyze').click();
ok(
  shown(doc.querySelector('#result')) && doc.querySelector('#result').classList.contains('is-error'),
  'click: URL primary submits the form (validation runs)'
);

// Vision: primary opens the screenshot picker through vision.js.
clickTab(window, 'vision');
let picks = 0;
doc.querySelector('#vision-file-input').click = () => { picks += 1; };
doc.querySelector('#vision-upload').click();
ok(picks === 1, 'click: Vision primary opens the screenshot picker exactly once');

// ------------------------------------------------- single, stable container
ok(
  doc.querySelectorAll('#text-input-actions').length === 1 &&
    doc.querySelector('#text-input-actions') === actionBar,
  'action bar: exactly one container, never duplicated or replaced'
);
ok(pageErrors.length === 0, 'page scripts stayed error-free through the run');

console.log(failures === 0 ? '\nPASS: all tab/action checks succeeded' : `\nFAIL: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
