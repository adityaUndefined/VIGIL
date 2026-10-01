import { JSDOM } from 'jsdom';

const ORIGIN = 'http://127.0.0.1:8000';
const results = [];
const check = (name, ok) => results.push([name, ok]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function loadPage(path) {
  const html = await (await fetch(`${ORIGIN}${path}`)).text();
  const dom = new JSDOM(html.replace(/<script[^>]*src=[^>]*><\/script>/g, ''), {
    url: `${ORIGIN}${path}`,
    runScripts: 'outside-only',
    pretendToBeVisual: true,
  });
  const w = dom.window;
  w.eval('var self = window;');
  w.matchMedia = () => ({ matches: false, addEventListener: () => {}, addListener: () => {} });
  w.fetch = (input, init) => {
    const url = typeof input === 'string' && input.startsWith('/') ? ORIGIN + input : input;
    return fetch(url, init);
  };
  w.eval(await (await fetch(`${ORIGIN}/theme.js`)).text() + '\n//# sourceURL=theme.js');
  w.eval(await (await fetch(`${ORIGIN}/app.js`)).text() + '\n//# sourceURL=app.js');
  await sleep(500); // let refreshModelStatus + loadTrendingScam settle
  return { w, d: w.document, q: (s) => w.document.querySelector(s) };
}

/* ---------- 1 · Landing page: nav chip + trending section ---------- */
{
  const { q } = await loadPage('/');
  const navChip = q('#ollama-status');
  check('index: nav model status chip present', !!navChip);
  check('index: nav chip shows offline label', navChip?.querySelector('.local-status-label')?.textContent.includes('MODEL OFFLINE'));
  check('index: nav chip styled as offline', /offline/.test(navChip?.className || ''));

  check('index: trending title loaded', q('#trending-scam-title')?.textContent === 'Delivery Fee Scam');
  check('index: trending threat level filled', q('#trending-scam-level')?.textContent.includes('High'));
  check('index: trending description filled', (q('#trending-scam-desc')?.textContent || '').length > 40);
  check('index: trending source marked offline fallback', (q('#trending-scam-source')?.textContent || '').includes('Offline example'));
}

/* ---------- 2 · Scanner: chip, model card, verification, poll merge ---------- */
{
  const { q } = await loadPage('/scanner.html');
  const navChip = q('#ollama-status');
  check('scanner: nav chip refreshed from /api/model', navChip?.querySelector('.local-status-label')?.textContent.includes('MODEL OFFLINE'));

  check('scanner: model card hidden before scan', q('.model-card')?.classList.contains('hidden'));

  q('#content-message').value = 'URGENT: verify your OTP now at http://192.168.0.1/secure or your account will be blocked';
  q('#analyze').click();
  await sleep(2200);

  check('scanner: decision rendered', ['ALLOW', 'WARN', 'DENY'].includes(q('#decision')?.textContent));
  check('scanner: result label = CONTENT ANALYSIS', q('#result-label')?.textContent === 'CONTENT ANALYSIS');

  const card = q('.model-card');
  check('scanner: model card visible after scan', !!card && !card.classList.contains('hidden'));
  check('scanner: model name shows Ollama model', (q('#model-name')?.textContent || '').startsWith('Ollama · qwen3.5:2b'));
  check('scanner: model badge = RULES FALLBACK (offline)', q('#model-badge')?.textContent === 'RULES FALLBACK');

  const note = q('#verification-note');
  check('scanner: verification note visible', !!note && !note.classList.contains('hidden'));
  check('scanner: verification copy explains fallback', (q('#verification-copy')?.textContent || '').includes('deterministic rules'));

  const chip = q('#model-status-chip');
  check('scanner: verdict status chip = RULES FALLBACK', chip?.textContent === 'RULES FALLBACK' && /offline/.test(chip?.className || ''));

  check('scanner: result tools visible', !!q('.result-tools') && !q('.result-tools').classList.contains('hidden'));
  check('scanner: copy-summary button present', !!q('#copy-summary'));
}

/* ---------- 3 · Agent Guard: same integration on check-action ---------- */
{
  const { q } = await loadPage('/agent-guard.html');
  check('agent-guard: nav chip present', !!q('#ollama-status'));

  q('#content-message').value = 'Invoice #8841 from vendor. Payment due immediately.';
  q('#check-action').click();
  await sleep(2200);

  check('agent-guard: decision rendered', ['ALLOW', 'WARN', 'DENY'].includes(q('#decision')?.textContent));
  check('agent-guard: result label = AGENT ACTION REVIEW', q('#result-label')?.textContent === 'AGENT ACTION REVIEW');
  check('agent-guard: model card visible', !!q('.model-card') && !q('.model-card').classList.contains('hidden'));
  check('agent-guard: model badge = RULES FALLBACK (offline)', q('#model-badge')?.textContent === 'RULES FALLBACK');
  check('agent-guard: verification note visible', !q('#verification-note')?.classList.contains('hidden'));
  check('agent-guard: verdict chip updated', q('#model-status-chip')?.textContent === 'RULES FALLBACK');
}

/* ---------- 4 · Served CSS carries the LLM component styles ---------- */
{
  const css = await (await fetch(`${ORIGIN}/style.css`)).text();
  for (const rule of ['.local-status {', '.local-status.ready', '.local-status.offline', '.model-card {', '.model-badge.ready', '.model-badge.pending', '.verification-note {', '.llm-findings {', '.result-tools {', '.trending-label']) {
    check(`style.css has ${rule}`, css.includes(rule));
  }
}

console.log('LLM UI INTEGRATION RESULTS:');
for (const [name, ok] of results) console.log(ok ? ' ✔' : ' ✘', name);
const failed = results.filter(([, ok]) => !ok).length;
console.log(failed ? `${failed} CHECK(S) FAILED` : 'ALL LLM UI CHECKS PASSED');
process.exit(failed ? 1 : 0);
