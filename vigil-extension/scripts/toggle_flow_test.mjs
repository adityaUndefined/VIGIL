import { JSDOM } from 'jsdom';
const ORIGIN = 'http://127.0.0.1:8000';

async function bootPage({ osDark, savedTheme }) {
  const html = await (await fetch(`${ORIGIN}/scanner.html`)).text();
  const dom = new JSDOM(html.replace(/<script[^>]*src=[^>]*><\/script>/g, ''), { url: `${ORIGIN}/scanner.html`, runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  w.eval('var self = window;');
  w.matchMedia = () => ({ matches: osDark, addEventListener: () => {}, addListener: () => {} });
  if (savedTheme) w.localStorage.setItem('vigil-theme', savedTheme);
  // run the shared theme controller exactly as the page does (sync, in head)
  const themeSrc = await (await fetch(`${ORIGIN}/theme.js`)).text();
  w.eval(themeSrc + '\n//# sourceURL=theme.js');
  w.fetch = (input, init) => {
    const url = typeof input === 'string' && input.startsWith('/') ? ORIGIN + input : input;
    return fetch(url, init);
  };
  w.eval(await (await fetch(`${ORIGIN}/app.js`)).text() + '\n//# sourceURL=app.js');
  await new Promise((r) => setTimeout(r, 300));
  return { w, d: w.document };
}

const results = [];
const check = (name, ok) => results.push([name, ok]);

// Scenario A: OS dark, first visit (no saved theme)
{
  const { w, d } = await bootPage({ osDark: true });
  check('A1: OS-dark first visit → auto dark', d.documentElement.dataset.theme === 'dark');
  d.querySelector('#theme-toggle').click();
  check('A2: toggle → light', d.documentElement.dataset.theme !== 'dark');
  check('A3: light saved', w.localStorage.getItem('vigil-theme') === 'light');
  // reload with saved light + OS dark
  const { d: d2 } = await bootPage({ osDark: true, savedTheme: 'light' });
  check('A4: reload keeps light (saved wins over OS)', d2.documentElement.dataset.theme !== 'dark');
  d2.querySelector('#theme-toggle').click();
  check('A5: toggle → dark again works', d2.documentElement.dataset.theme === 'dark');
}

// Scenario B: OS light, plain toggle round-trip
{
  const { w, d } = await bootPage({ osDark: false });
  check('B1: starts light', d.documentElement.dataset.theme !== 'dark');
  d.querySelector('#theme-toggle').click();
  check('B2: → dark', d.documentElement.dataset.theme === 'dark');
  d.querySelector('#theme-toggle').click();
  check('B3: → back to light', d.documentElement.dataset.theme !== 'dark');
  check('B4: saved light', w.localStorage.getItem('vigil-theme') === 'light');
}

console.log('TOGGLE FLOW RESULTS:');
for (const [name, ok] of results) console.log(ok ? ' ✔' : ' ✘', name);
console.log(results.every(([, ok]) => ok) ? 'ALL TOGGLE CHECKS PASSED' : 'SOME CHECKS FAILED');
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
