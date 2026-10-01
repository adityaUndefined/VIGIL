// background.js — the service worker owns the network call (guide Step 7).
// A content script's fetch is subject to the page's CORS and mixed-content
// rules; the service worker's is not (host_permissions above).
const GUARD_URL = "http://127.0.0.1:8000/guard";

// Fail closed, exactly like the Python client in agent/. Returning
// "WARN / guard_unreachable" used to let every action through whenever VIGIL
// was down, which defeats the point of the gate.
function unreachable(detail) {
  return {
    decision: "DENY",
    machine_tag: "VIGIL_UNREACHABLE",
    reason: "VIGIL could not be reached, so the action was refused.",
    evidence: [{
      id: "GUARD-UNREACHABLE",
      type: "guard_unreachable",
      severity: "critical",
      fact: "The local VIGIL guard could not be consulted, so the action was blocked.",
    }],
    explanation: {
      summary: "VIGIL is not reachable, so this action was blocked.",
      cited_evidence_ids: ["GUARD-UNREACHABLE"],
      source: "guard_extension",
    },
    error: detail,
  };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "VIGIL_GUARD") return;
  fetch(GUARD_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg.payload),
  })
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then((verdict) => {
      // A response without a decision is not a permission slip.
      if (!verdict || typeof verdict.decision !== "string") {
        sendResponse(unreachable("guard response was not a decision object"));
        return;
      }
      sendResponse(verdict);
    })
    .catch((e) => sendResponse(unreachable(String((e && e.message) || e))));
  return true; // keeps the channel open for the async reply
});
