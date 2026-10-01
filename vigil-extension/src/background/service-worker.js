/**
 * VIGIL Security — MV3 background service worker.
 *
 * Responsibilities (kept deliberately small — no analysis happens here):
 *   - context menu ("Scan with VIGIL") lifecycle
 *   - side panel opening + handoff of user-initiated scan requests
 *   - on-demand tab operations for the side panel (tab info, page
 *     extraction, screenshot capture) via message passing
 *
 * The service worker is event-driven and idles between user actions; there
 * are no timers, scans, or network calls running in the background.
 *
 * NOTE: extractPageData.js is importScripts'd so the function object can be
 * passed to chrome.scripting.executeScript({func}) — Chrome serializes the
 * function's source and runs it inside the page. The page extractor itself
 * never reads input values, keystrokes, or form contents (see the file for
 * the full privacy contract).
 */
'use strict';

importScripts('../../config/config.js', '../../src/utils/extractPageData.js');

// ---------------------------------------------------------------------
// Side panel + icon behavior
// ---------------------------------------------------------------------

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error) => console.error('VIGIL: could not set panel behavior', error));

// ---------------------------------------------------------------------
// Context menu: "Scan with VIGIL" (selected text)
// ---------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'vigil-scan-selection',
    title: 'Scan with VIGIL',
    contexts: ['selection']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'vigil-scan-selection') return;
  const text = (info.selectionText || '').trim();
  if (!text) return;

  // Transient handoff (in-memory, cleared with the browser session) so the
  // panel can pick the request up even if it is still loading.
  const payload = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    text,
    sourceTitle: (tab && tab.title) || ''
  };
  chrome.storage.session.set({ vigilPendingSelection: payload }).catch(() => {});

  try {
    if (tab && tab.windowId !== undefined) {
      await chrome.sidePanel.open({ windowId: tab.windowId });
      if (tab.id !== undefined) {
        await chrome.sidePanel.setOptions({ tabId: tab.id, path: 'src/sidepanel/sidepanel.html' });
      }
    }
  } catch (error) {
    // Some surfaces (e.g. PDF viewer) refuse sidePanel.open(); the user can
    // still open the panel from the toolbar — never crash over it.
    console.warn('VIGIL: could not auto-open side panel', error);
  }

  // Deliver immediately and again shortly after (panel may be mid-load).
  const deliver = () => {
    chrome.runtime.sendMessage({ type: 'vigil-scan-selection', ...payload }).catch(() => {
      /* panel not ready; it will pull vigilPendingSelection on load */
    });
  };
  deliver();
  setTimeout(deliver, 700);
});

// ---------------------------------------------------------------------
// Tab helpers for the side panel
// ---------------------------------------------------------------------

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

function hasActiveTabFileAccess() {
  return chrome.extension.isAllowedFileSchemeAccess();
}

const RESTRICTED_URL_PATTERN = /^(chrome|edge|about|view-source|devtools|chrome-extension)/i;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message && message.type) {
      case 'vigil-get-tab': {
        try {
          const tab = await getActiveTab();
          sendResponse({ ok: true, tab: tab ? { id: tab.id, url: tab.url, title: tab.title } : null });
        } catch (error) {
          sendResponse({ ok: false, error: String((error && error.message) || error) });
        }
        return;
      }

      case 'vigil-extract-page': {
        try {
          const tab = await getActiveTab();
          if (!tab || typeof tab.id !== 'number') {
            sendResponse({ ok: false, error: 'VIGIL couldn\'t find an active page to scan.' });
            return;
          }
          const url = tab.url || '';
          const restricted = RESTRICTED_URL_PATTERN.test(url)
            || url.startsWith('https://chromewebstore.google.com')
            || (url.startsWith('file:') && !(await hasActiveTabFileAccess()));
          if (!/^https?:/i.test(url) || restricted) {
            sendResponse({
              ok: false,
              error: 'VIGIL couldn\'t analyze this page. Browser pages and the Chrome Web Store are off limits for scanning.',
              kind: 'restricted'
            });
            return;
          }
          const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: vigilExtractPageData,
            args: [message.maxChars || 200000]
          });
          const pageData = results && results[0] && results[0].result;
          if (!pageData || !pageData.content) {
            sendResponse({ ok: false, error: 'VIGIL couldn\'t read this page\'s content. It may block extensions.' });
            return;
          }
          sendResponse({ ok: true, pageData });
        } catch (error) {
          const messageText = String((error && error.message) || error);
          const permissionProblem = /cannot access|permission|host|origin/i.test(messageText);
          sendResponse({
            ok: false,
            error: permissionProblem
              ? 'VIGIL doesn\'t have permission to read this page. Grant site access from Settings, then try again.'
              : 'VIGIL couldn\'t analyze this page.',
            kind: permissionProblem ? 'permission' : 'extract'
          });
        }
        return;
      }

      case 'vigil-capture-tab': {
        try {
          const tab = await getActiveTab();
          const windowId = (tab && tab.windowId) || (await chrome.windows.getCurrent()).id;
          const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
          sendResponse({ ok: true, dataUrl, pageUrl: (tab && tab.url) || '', pageTitle: (tab && tab.title) || '' });
        } catch (error) {
          const messageText = String((error && error.message) || error);
          sendResponse({
            ok: false,
            error: /restricted|cannot capture|protected|not allowed/i.test(messageText)
              ? 'This page cannot be captured. Browser pages and protected sites block screenshots.'
              : 'Screenshot capture failed. Make sure the VIGIL window is in the foreground and try again.',
            kind: 'capture'
          });
        }
        return;
      }

      case 'vigil-request-optional-permissions': {
        try {
          const granted = await chrome.permissions.request({ origins: message.origins || [] });
          sendResponse({ ok: granted });
        } catch (error) {
          sendResponse({ ok: false, error: String((error && error.message) || error) });
        }
        return;
      }

      default:
        return; // unknown message — ignore
    }
  })();
  return true; // async sendResponse
});
