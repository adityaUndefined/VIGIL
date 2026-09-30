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

## Features

- **Message analysis**  
  Review suspicious messages and identify security signals.

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

## How It Works

```text
Message / URL / HTML
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
