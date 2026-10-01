import { JSDOM } from 'jsdom';
const ORIGIN = 'http://127.0.0.1:8000';
const html = await (await fetch(`${ORIGIN}/scanner.html`)).text();
const dom = new JSDOM(html.replace(/<script[^>]*src=[^>]*><\/script>/g, ''), { url: `${ORIGIN}/scanner.html`, runScripts: 'outside-only', pretendToBeVisual: true });
const w = dom.window;
w.eval('var self = window;');
w.matchMedia = () => ({ matches: false, addEventListener: () => {}, addListener: () => {} });
// Resolve the page's RELATIVE URLs against the origin (Node fetch can't do that; browsers can).
w.fetch = (input, init) => {
  const url = typeof input === 'string' && input.startsWith('/') ? ORIGIN + input : input;
  return fetch(url, init);
};
for (const f of ['app.js', 'vision.js']) {
  w.eval(await (await fetch(`${ORIGIN}/${f}`)).text() + `\n//# sourceURL=${f}`);
}
await new Promise((r) => setTimeout(r, 500));
const d = w.document;
const q = (s) => d.querySelector(s);
const results = [];
const check = (name, ok) => results.push([name, ok]);

q('[data-mode="url"]').click();
check('URL tab switches', !q('#url-panel').hidden && q('#message-panel').hidden);
q('#mode-vision').click();
check('Vision tab opens', !q('#vision-panel').hidden);
q('[data-mode="message"]').click();
check('Message tab after Vision works', !q('#message-panel').hidden && q('#vision-panel').hidden);

q('#content-message').value = 'URGENT: your account will be suspended. verify your password now';
q('#analyze').click();
await new Promise((r) => setTimeout(r, 2500));
check('live scan renders verdict', !q('#result').hidden && (q('#decision')?.textContent || '').length > 0);
check('verdict is ALLOW/WARN/DENY', ['ALLOW', 'WARN', 'DENY'].includes(q('#decision').textContent));
check('DENY for credential-harvest text', q('#decision').textContent === 'DENY');
check('evidence rendered', (q('#evidence-list')?.children.length || 0) >= 1);

console.log('LIVE RESULTS (real backend, relative URLs resolved):');
for (const [name, ok] of results) console.log(ok ? ' ✔' : ' ✘', name);
console.log(results.every(([, ok]) => ok) ? 'ALL LIVE CHECKS PASSED' : 'SOME CHECKS FAILED');
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
