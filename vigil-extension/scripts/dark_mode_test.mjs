import { JSDOM } from 'jsdom';
const ORIGIN = 'http://127.0.0.1:8000';
const html = await (await fetch(`${ORIGIN}/scanner.html`)).text();
const dom = new JSDOM(html.replace(/<script[^>]*src=[^>]*><\/script>/g, ''), { url: `${ORIGIN}/scanner.html`, runScripts: 'outside-only', pretendToBeVisual: true });
const w = dom.window;
w.eval('var self = window;');
w.matchMedia = () => ({ matches: false, addEventListener: () => {}, addListener: () => {} });
// in-memory localStorage (jsdom has one, but ensure clean)
w.localStorage.clear();
w.fetch = (input, init) => {
  const url = typeof input === 'string' && input.startsWith('/') ? ORIGIN + input : input;
  return fetch(url, init);
};
w.eval(await (await fetch(`${ORIGIN}/theme.js`)).text() + '\n//# sourceURL=theme.js');
w.eval(await (await fetch(`${ORIGIN}/app.js`)).text() + '\n//# sourceURL=app.js');
await new Promise((r) => setTimeout(r, 400));
const d = w.document;
const q = (s) => d.querySelector(s);
const results = [];
const check = (name, ok) => results.push([name, ok]);

const toggle = q('#theme-toggle');
check('toggle button visible (not hidden)', !!toggle && !toggle.classList.contains('hidden'));
check('starts in light theme', d.documentElement.dataset.theme !== 'dark');
check('icon shows moon on light', toggle.textContent.includes('🌙'));

toggle.click();
check('click flips to dark', d.documentElement.dataset.theme === 'dark');
check('icon flips to sun on dark', toggle.textContent.includes('☀️'));
check('theme persisted', w.localStorage.getItem('vigil-theme') === 'dark');

toggle.click();
check('click flips back to light', d.documentElement.dataset.theme !== 'dark');
check('persistence cleared to light', w.localStorage.getItem('vigil-theme') === 'light');
toggle.click(); // leave dark for CSS checks

// CSS rule presence in served stylesheet (dark overrides for light-only utilities)
const css = await (await fetch(`${ORIGIN}/style.css`)).text();
check('dark overrides for .bg-white', css.includes(':root[data-theme="dark"] .bg-white'));
check('dark overrides for .text-black/.text-gray-500', css.includes('.text-black') && css.includes('.text-gray-500'));
check('dark allow/warn/deny colors defined', ['--allow-bg', '--warn-bg', '--deny-bg'].every((v) => css.split(':root[data-theme="dark"]')[1].includes(v)));
check('theme-toggle style defined', css.includes('.theme-toggle'));

// scan still works in dark mode
q('#content-message').value = 'URGENT verify your OTP now';
q('#analyze').click();
await new Promise((r) => setTimeout(r, 2000));
check('scan works in dark mode', ['ALLOW', 'WARN', 'DENY'].includes(q('#decision').textContent));

console.log('DARK MODE RESULTS:');
for (const [name, ok] of results) console.log(ok ? ' ✔' : ' ✘', name);
console.log(results.every(([, ok]) => ok) ? 'ALL DARK MODE CHECKS PASSED' : 'SOME CHECKS FAILED');
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
