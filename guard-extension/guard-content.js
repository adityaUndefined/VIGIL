// guard-content.js — collect what a human cannot see, ask the guard, enforce
// the answer (guide Step 7).
//  (a) any page script/agent proposing an action via window.postMessage
//      { type: "VIGIL_PROPOSE_ACTION", id, action } gets a VIGIL_VERDICT back,
//  (b) form submits are held until the guard answers; DENY cancels them.

const GUARD_TRIVIALLY_SAFE = new Set(["", "about:blank"]);
const TAG_BLACKLIST = ["SCRIPT", "STYLE", "NOSCRIPT"];

function isHiddenFromHuman(el) {
  // both option spellings are passed because Chromium renamed them across versions
  const opts = { checkOpacity: true, checkVisibilityCSS: true, opacityProperty: true, visibilityProperty: true };
  if (typeof el.checkVisibility === "function" && !el.checkVisibility(opts)) return true;
  if (parseFloat(getComputedStyle(el).fontSize) < 2) return true;
  const r = el.getBoundingClientRect();
  return r.right + window.scrollX < 0 || r.bottom + window.scrollY < 0;   // pushed off-screen
}

function collectHiddenText() {
  if (!document.body) return "";
  const hidden = [];
  const walker = document.createTreeWalker(
    document.body, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const text = (node.textContent || "").trim();
    if (!text) continue;
    if (node.nodeType === Node.COMMENT_NODE) { hidden.push(text); continue; }
    const el = node.parentElement;
    if (!el || TAG_BLACKLIST.includes(el.tagName)) continue;
    if (isHiddenFromHuman(el)) hidden.push(text);
  }
  return hidden.join(" ").slice(0, 4000);
}

const askGuard = (action) =>
  chrome.runtime.sendMessage({
    type: "VIGIL_GUARD",
    payload: { source: { url: location.href, hidden_text: collectHiddenText() }, action },
  });

function showBlock(verdict) {
  const host = document.createElement("div");
  const root = host.attachShadow({ mode: "closed" });   // page CSS cannot touch it
  const style = document.createElement("style");
  style.textContent =
    ".box{position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:360px;" +
    "font:14px system-ui,sans-serif;background:#1b1020;color:#fff;border:2px solid #ff5a5f;" +
    "border-radius:12px;padding:14px 16px}.t{font-weight:700;color:#ff8a8f}.s{opacity:.75;font-size:12px}";
  const box = document.createElement("div");
  box.className = "box";
  const title = Object.assign(document.createElement("div"),
    { className: "t", textContent: "VIGIL blocked an automated action" });
  const msg = Object.assign(document.createElement("p"),
    { textContent: (verdict.explanation && verdict.explanation.summary) || verdict.summary || "This action was denied by the local VIGIL guard." });
  const ids = Object.assign(document.createElement("div"),
    { className: "s", textContent: "Evidence: " + (verdict.evidence || []).map((e) => e.id).join(", ") });
  box.append(title, msg, ids);
  root.append(style, box);
  document.documentElement.appendChild(host);
}

// Readiness markers so tests/drivers can wait for the content script.
// DOM is shared between the page world and the isolated world; window props
// are not, so the dataset marker is the one visible from page scripts.
document.documentElement.dataset.vigilContent = "1";
window.__vigilContentReady = true;

// (a) Any agent or script on the page proposes an action through this bridge.
window.addEventListener("message", async (e) => {
  if (e.source !== window || e.data?.type !== "VIGIL_PROPOSE_ACTION") return;
  const verdict = await askGuard(e.data.action);
  window.postMessage({ type: "VIGIL_VERDICT", id: e.data.id, verdict }, "*");
  if (verdict?.decision === "DENY") showBlock(verdict);
});

// (b) Form submits are held until the guard answers.
document.addEventListener("submit", async (e) => {
  const form = e.target;
  if (!(form instanceof HTMLFormElement) || form.dataset.vigilOk) return;
  e.preventDefault();
  const verdict = await askGuard({
    tool: "submit_form",
    args: { url: GUARD_TRIVIALLY_SAFE.has(form.action) ? location.href : form.action,
            fields: [...form.elements].map((x) => x.name).filter(Boolean).join(",") },
  });
  if (verdict?.decision === "DENY") return showBlock(verdict);
  form.dataset.vigilOk = "1";
  form.requestSubmit();
}, true);
