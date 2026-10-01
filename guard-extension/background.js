// background.js — the service worker owns the network call (guide Step 7).
// A content script's fetch is subject to the page's CORS and mixed-content
// rules; the service worker's is not (host_permissions above).
const GUARD_URL = "http://127.0.0.1:8000/guard";

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "VIGIL_GUARD") return;
  fetch(GUARD_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg.payload),
  })
    .then((r) => r.json())
    .then(sendResponse)
    .catch(() => sendResponse({ decision: "WARN", error: "guard_unreachable" }));
  return true; // keeps the channel open for the async reply
});
