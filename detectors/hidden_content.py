# detectors/hidden_content.py — hidden-content detector (guide Step 3).
# Pure Python standard library. Two entry points:
#   - source["hidden_text"] is set: the extension already worked out what is
#     invisible to a human (most accurate path), so we trust it.
#   - otherwise raw HTML: we parse it ourselves and extract hidden text.
import re
from html.parser import HTMLParser

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from facts import FACTS

ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?![.\d])"
    r"|font-size\s*:\s*0(?:px|pt|em|rem)?\s*(?:;|$)"
    r"|(?:left|top|text-indent)\s*:\s*-\d{3,}px",
    re.I,
)
SKIP = {"script", "style", "noscript"}
VOID = {"br", "img", "hr", "input", "meta", "link", "source", "wbr"}

INSTRUCTION_PATTERNS = [
    ("HID-INJ-01", re.compile(r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules|policy)", re.I)),
    ("HID-INJ-02", re.compile(r"\b(?:system|assistant|copilot|agent)\s*[:,]", re.I)),
    ("HID-INJ-03", re.compile(r"\b(?:forward|send|share|reply with|submit)\b.{0,60}\b(?:otp|password|passcode|pin|cvv|upi|credentials?)\b", re.I)),
    ("HID-INJ-04", re.compile(r"do not (?:tell|inform|mention|alert|notify)\b.{0,30}\b(?:user|human|owner)", re.I)),
]


class HiddenTextExtractor(HTMLParser):
    """Walks HTML and collects text that styling/attributes hide from a human."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []                      # list of (tag, hidden?)
        self.hidden, self.comments = [], []

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        a = dict(attrs)
        parent_hidden = self.stack[-1][1] if self.stack else False
        own_hidden = bool(
            HIDDEN_STYLE.search(a.get("style") or "")
            or "hidden" in a
            or a.get("aria-hidden") == "true"
        )
        self.stack.append((tag, parent_hidden or own_hidden))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        text = data.strip()
        if not text or any(t in SKIP for t, _ in self.stack):
            return
        if self.stack and self.stack[-1][1]:
            self.hidden.append(text)

    def handle_comment(self, data):
        self.comments.append(data.strip())


def check(source):
    """Returns {"evidence": [...], "hidden_text": str, "raw": str}."""
    if source.get("hidden_text") is not None:     # extension path
        hidden_text = (source.get("hidden_text") or "").strip()
        raw = hidden_text
    else:                                         # raw HTML path (web app / agent)
        parser = HiddenTextExtractor()
        try:
            parser.feed(source.get("html") or "")
        except Exception:
            pass                                  # malformed HTML: fall through with what we have
        hidden_text = " ".join(parser.hidden + parser.comments).strip()
        raw = source.get("html") or ""

    evidence = []
    if hidden_text:
        evidence.append({"id": "HID-001", "signal": FACTS["HID-001"],
                         "detail": hidden_text[:200], "severity": "medium"})
    # Attackers split keywords with zero-width characters; match against a
    # normalized copy so "i\u200bg\u200bnore" still reads as "ignore".
    normalized = ZERO_WIDTH.sub("", hidden_text)
    for eid, rx in INSTRUCTION_PATTERNS:
        m = rx.search(normalized)
        if m:
            evidence.append({"id": eid, "signal": FACTS[eid],
                             "detail": m.group(0)[:120], "severity": "critical"})
    if len(ZERO_WIDTH.findall(raw)) >= 3:
        evidence.append({"id": "HID-ZW-01", "signal": FACTS["HID-ZW-01"], "severity": "medium"})
    return {"evidence": evidence, "hidden_text": hidden_text, "raw": raw}
