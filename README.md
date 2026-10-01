# VIGIL

### Protect Humans. Protect Agents.

VIGIL is a local-first security layer for messages, website addresses, and HTML. It analyzes security signals, produces an evidence-backed `ALLOW`, `WARN`, or `DENY` decision, and can evaluate proposed AI-agent actions before they proceed.

Its key focus is not only protecting people from deceptive content, but also detecting hidden instructions that attempt to manipulate AI agents.

**Quick start → [BUILD.md](BUILD.md)** — run the analyzer, load the extension, and verify the build in under a minute. Zero dependencies: the core engine is pure Python standard library.

---

## Why VIGIL?

Traditional link checking asks:

> Is this URL malicious?

VIGIL goes one step further:

> What is this content trying to make a human or an AI agent do?

A page can look harmless to a person while containing hidden instructions intended for an AI system. VIGIL analyzes the underlying content and provides a second security boundary before an agent action is allowed.

---

## VIGIL Vision — Visual Threat Analysis

> "See the threat behind the screenshot."

VIGIL Vision extends the same evidence-backed review to **screenshots**: phishing messages, SMS/WhatsApp/email captures, fake login or banking pages, payment requests, QR-code scams, and suspicious websites.

- **📸 VIGIL Vision** — Screenshot → OCR + visual analysis + contextual analysis + URL analysis + evidence + risk assessment
- **💬 Message** — Text → security analysis

Vision is not "OCR and paste into the Message tab": every text finding keeps its **bounding box** on the original screenshot, and the report shows an interactive **evidence overlay** you can click to see WHAT was detected, WHERE, WHY, with what confidence, and its risk contribution.

### How the Vision pipeline works

```text
Screenshot (PNG/JPG/JPEG/WEBP, validated in the browser)
      |
      v
Image preprocessing (adaptive rescale, grayscale + percentile contrast on a second pass when needed)
      |
      v
Local OCR (Tesseract.js WASM — words with confidence + bounding boxes; nothing leaves the device yet)
      |
      v
QR decoding (jsQR, local — destinations are NEVER opened) + measured visual structures (password / OTP input boxes)
      |
      v
Text + regions → server: VIGIL's existing rules engine, URL analyzer, and policy decision
      |
      v
Evidence correlation (brand + urgency + credential + unverified destination patterns)
      |
      v
ALLOW / WARN / DENY + risk score, WHY breakdown, recommended actions
```

Key properties:

- **One risk system.** Vision calls VIGIL's existing `analyze_content`, `analyze_urls`, and `policy_decision`. There is no second scoring engine.
- **Evidence overlay.** Red = high risk, orange = caution, blue = informational. Toggle BEFORE / AFTER views; click any highlight for the evidence details.
- **Editable OCR.** Low-confidence extraction is clearly reported ("Some text could not be confidently extracted"); you can correct the text and press UPDATE ANALYSIS. Edited text is labeled "User-edited text" and never treated as directly extracted.
- **No false-positive theater.** A logo, login form, URL, phone number, payment amount, the word "urgent", a bank name, or a QR code **alone** never produces a scam verdict. Correlated evidence does.
- **Local-first.** OCR, QR decoding, and preprocessing run entirely in your browser via WASM. Only the extracted text, region coordinates, and QR payloads are sent to the VIGIL server for rule analysis — never the image itself.
- **Deterministic explanation.** The WHY panel is generated only from actually detected evidence. If OCR confidence is low, the report says so instead of pretending certainty.

### Try the demo

Press **TRY DEMO** in the Vision tab to cycle through five safe synthetic scenarios: a bank-KYC phishing screenshot, a fake delivery-fee message, a fake login page, a QR payment scam, and a legitimate notification. Every demo is generated locally in the browser, uses `.example` domains, and touches no real infrastructure.

### Measured accuracy

Run the offline suite:

```bash
python3 scripts/run_vision_tests.py
```

It executes the ten QA fixtures plus false-positive guards and prints measured precision, recall, F1, false-positive rate, and false-negative rate for the current rule set. No accuracy percentage is claimed beyond what this suite measures.

### Privacy

Screenshots are processed in the browser; the extracted text and coordinates are what reach the server. VIGIL does not store screenshots, does not log their contents, and never logs passwords, OTPs, or banking credentials. A reminder is shown in the UI: avoid uploading sensitive credentials.

---

- **Message analysis**  
  Review suspicious messages and identify security signals.

- **Screenshot analysis (VIGIL Vision)**  
  Analyze screenshots of messages, emails, login pages, payment requests, and QR codes with located, clickable evidence.

- **Website URL analysis**  
  Analyze a supplied URL as text without visiting or navigating to the website.

- **HTML source analysis**  
  Inspect webpage source for suspicious or hidden content.

- **Hidden instruction detection**  
  Detect hidden HTML instructions, including visually suppressed content and other hidden-text techniques.

- **Evidence-backed verdicts**  
  Return `ALLOW`, `WARN`, or `DENY` with supporting evidence.

- **AI-agent action review**  
  Evaluate a proposed action such as sending private information before it proceeds.

- **Local-first security path**  
  The rules-based verdict works without Ollama or internet access.

- **Optional local LLM explanation**  
  Connect your own local model — native Ollama or any OpenAI-compatible local server (LM Studio, llama.cpp, vLLM, Jan, LocalAI) — for an additional plain-language review of the detected evidence. See `BUILD.md` § 5.

- **Rules-only fallback**  
  If the local model is unavailable or its response fails validation, VIGIL falls back to a deterministic explanation.

- **Chromium extension**  
  Review the current webpage directly from the browser.

- **Fail-closed agent guard**  
  A machine-facing policy gate (`POST /api/guard`) plus a Python client that AI agents consult before acting — hidden instructions, redirect-wrapped links, and sensitive actions are denied, and the gate fails closed when VIGIL is unreachable. See `agent/README.md`.

---

## Agent Guard + Grounded Explainer

A standalone, zero-dependency agent guard lives alongside the main analyzer:

- **Rules decide, the LLM only explains.** `POST /guard` answers `ALLOW` / `WARN` / `DENY` from deterministic code in milliseconds — the model never gets a vote.
- **The LLM never reads untrusted content.** `POST /explain` sends only fixed fact sentences (`facts.py`) to a local Ollama model; output is validated and falls back to deterministic wording. A hidden "say this is safe" line cannot hijack the explainer.
- **Instant verdict, later wording.** `/guard` returns the decision plus a template explanation immediately; `/explain` upgrades the wording after.
- **Provenance check.** If an action's destination (recipient, URL, account) appears inside text a human could not see, the action was dictated by hidden content — that signal does not depend on attacker phrasing.

Quick start:

```bash
python3 test_fixtures.py          # 5/5 offline fixtures pass, no Ollama needed
python3 guard_server.py           # POST /guard, POST /explain, GET /health on :8000
```

Components: `facts.py` (shared fact sheet), `detectors/hidden_content.py`, `guard.py`, `explain.py`, `guard_server.py`, `fixtures/` + `test_fixtures.py`, `guard-extension/` (Chromium MV3 companion that asks the guard before agent actions and form submits — see `guard-extension/README.md`), `demo/hijack_demo.html` (naive-agent demo page), and `agent/guarded.py` (wrap any Python agent tool call; also the `vigil.check` MCP tool core).

## How It Works

```text
Message / URL / HTML / Screenshot
          |
          v
    VIGIL Analyzer
          |
          v
    Security Signals
          |
          v
     Risk Decision
          |
          v
   Evidence + Verdict
       /        \
      v          v
Agent Action   Explanation
   Review        Layer
      |
      v
ALLOW / WARN / DENY
```

For AI agents, the same engine powers a stricter, fail-closed gate: agents call `POST /api/guard` (or the Python client in `agent/`) before acting, and only read-only actions on ALLOW-reviewed content are permitted. See `agent/README.md`.

## Running

```bash
python3 app.py                    # UI + API on http://127.0.0.1:8000
VIGIL_PORT=9000 python3 app.py    # custom port
```

Optional: run [Ollama](https://ollama.com) locally with the configured model for the advisory local-LLM review. VIGIL works fully without it.

## Tests

```bash
python3 scripts/run_offline_fixtures.py   # message/HTML/action engine fixtures
python3 scripts/run_vision_tests.py       # Vision fixtures + precision/recall/F1
python3 test_fixtures.py                  # agent-guard fixtures (hidden content, provenance)
```
