const apiBase = 'http://127.0.0.1:8000';
let activeTab = null;

const title = document.querySelector('#page-title');
const urlLabel = document.querySelector('#page-url');
const statusLabel = document.querySelector('#status');
const reviewButton = document.querySelector('#review');
const blockButton = document.querySelector('#block');

async function activePage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab;
  title.textContent = tab?.title || 'Current page';
  urlLabel.textContent = tab?.url || 'This browser page cannot be inspected.';
}
activePage();

reviewButton.addEventListener('click', async () => {
  reviewButton.disabled = true;
  reviewButton.setAttribute('aria-busy', 'true');
  reviewButton.textContent = 'Reviewing page…';
  document.querySelector('#result').classList.add('hidden');
  statusLabel.textContent = 'Reading page content locally…';
  blockButton.classList.add('hidden');
  try {
    const [page] = await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: () => ({
        url: location.href,
        title: document.title,
        html: document.documentElement?.outerHTML?.slice(0, 120000) || document.body?.innerText || ''
      })
    });
    const content = `Page URL: ${page.result.url}\nPage title: ${page.result.title}\n${page.result.html}`;
    const response = await fetch(`${apiBase}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'VIGIL could not analyze the page.');
    document.querySelector('#result').classList.remove('hidden');
    const decision = document.querySelector('#decision');
    decision.textContent = result.decision;
    decision.className = result.decision.toLowerCase();
    document.querySelector('#summary').textContent = result.explanation.text;
    const list = document.querySelector('#evidence');
    list.replaceChildren();
    result.evidence.forEach((item) => {
      if (item.severity === 'info') return;
      const li = document.createElement('li');
      li.textContent = item.fact;
      list.append(li);
    });
    blockButton.classList.toggle('hidden', result.decision !== 'DENY');
    statusLabel.textContent = result.local_model?.status === 'connected'
      ? `Reviewed locally with ${result.local_model.name}.`
      : 'Reviewed by VIGIL’s local rules. No page content was sent to a cloud service.';
  } catch (error) {
    statusLabel.textContent = error.message.includes('Cannot access')
      ? 'This browser page restricts extensions. Try the VIGIL demo page or a regular website.'
      : `Could not reach VIGIL at ${apiBase}. Start the local app and try again.`;
  } finally {
    reviewButton.disabled = false;
    reviewButton.removeAttribute('aria-busy');
    reviewButton.textContent = 'Review this page';
  }
});

blockButton.addEventListener('click', async () => {
  if (!activeTab?.id) return;
  const blockedUrl = chrome.runtime.getURL('blocked.html') + `?target=${encodeURIComponent(activeTab.url || '')}`;
  await chrome.tabs.update(activeTab.id, { url: blockedUrl });
});
