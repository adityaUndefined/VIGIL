# guard.py — the deterministic decision core (guide Step 4).
# Rules decide, the LLM only explains: this module never touches a model.
import time

from detectors import hidden_content
from facts import FACTS

SENSITIVE_TOOLS = {"forward_email", "send_email", "submit_form", "make_payment",
                   "share_file", "open_url", "autofill"}
RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def provenance_hits(action, hidden_text):
    """Action targets (recipients, URLs, accounts) that appear inside text the
    user could not see — the phrasing-independent hijack signal."""
    hidden = hidden_text.lower()
    hits = []
    for name, value in (action.get("args") or {}).items():
        v = str(value).strip().lower()
        if len(v) >= 6 and v in hidden:
            hits.append(name)
    return hits


def guard(source, action):
    t0 = time.time()
    action = action or {}
    found = hidden_content.check(source or {})
    evidence = list(found["evidence"])

    tool = action.get("tool", "")
    sensitive = tool in SENSITIVE_TOOLS
    injected = any(e["id"].startswith("HID-INJ") for e in evidence)
    hits = provenance_hits(action, found["hidden_text"])

    if sensitive:
        evidence.append({"id": "ACT-SENS-01", "signal": FACTS["ACT-SENS-01"], "severity": "medium"})
    if hits:
        evidence.append({"id": "ACT-PROV-01", "signal": FACTS["ACT-PROV-01"], "severity": "critical"})

    # KEEP YOUR EXISTING credential / payment rules here and append their evidence too.

    if hits or (injected and sensitive):
        decision = "DENY"
    elif injected:
        decision = "WARN"
    else:
        decision = "ALLOW"   # ordinary hidden text (an email preheader) alone is not enough to block

    evidence.sort(key=lambda e: -RANK[e["severity"]])
    return {"decision": decision, "evidence": evidence,
            "latency_ms": round((time.time() - t0) * 1000)}
