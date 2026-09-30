# VIGIL — Build & Run Guide

Step-by-step instructions to build, run, and verify every component of VIGIL locally and in deployment.

## Project Components

| Component | Location | What it is |
|---|---|---|
| Analyzer server | `app.py` | Local Python HTTP server — the rules engine + optional Ollama review |
| Chromium extension | `extension/` | Browser extension to review the current page |
| Web UI | `web/` | Browser frontend (deployed on Vercel) |
| Serverless API | `api/` | Vercel Python functions backing the web UI (`/api/*`) |
| Offline verification | `scripts/run_offline_fixtures.py` | Deterministic fixture tests, no network or model required |
| Design generation | `scripts/generate-vigil-design.mjs` | Optional UI design regeneration via Stitch SDK |

---

## Prerequisites

- **Python 3.9+** — that's it for the core server. VIGIL's analyzer uses **only the Python standard library**; there is no `pip install` step.
- **Chromium-based browser** (Chrome, Brave, Edge, Chromium) — for the extension.
- **Node.js + npm** — only needed for the optional design script.
- **Vercel CLI** — only needed to run/deploy the web UI + serverless API.
- **Ollama** (optional) — for local LLM explanations. VIGIL works fully without it.

---

## 1. Run the Local Analyzer Server

```bash
git clone https://github.com/adityaUndefined/VIGIL.git
cd VIGIL
python3 app.py
```

Output:

```
VIGIL running at http://127.0.0.1:8000
```

The server is now live with the full rules engine. No internet, no model, no dependencies needed.

**Configuration (environment variables):**

| Variable | Default | Purpose |
|---|---|---|
| `VIGIL_PORT` | `8000` | Server port |
| `VIGIL_HOST` | `127.0.0.1` | Bind address |
| `VIGIL_OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama endpoint |
| `VIGIL_OLLAMA_MODEL` | `qwen3.5:2b` | Local model used for advisory review |

Example — run on a different port:

```bash
VIGIL_PORT=9000 python3 app.py
```

> ⚠️ The extension's `host_permissions` is pinned to `http://127.0.0.1:8000/*`. If you change the port, update `extension/manifest.json` to match.

---

## 2. Load the Chromium Extension

1. Start the local server first (step 1) — the extension talks to `http://127.0.0.1:8000`.
2. Open `chrome://extensions` in your Chromium browser.
3. Enable **Developer mode** (toggle, top-right).
4. Click **Load unpacked**.
5. Select the `extension/` directory of this repo.
6. Pin "VIGIL Page Review" to the toolbar. Navigate to any page and click the icon to get an `ALLOW` / `WARN` / `DENY` review.

---

## 3. Run the Web UI

The web frontend (`web/`) calls relative `/api/*` endpoints, which are served by the Python functions in `api/`. Two ways to run it:

### Option A — Deployed (zero setup)

The live demo is already up: **https://vigil-jet-three.vercel.app**

### Option B — Local via Vercel dev

```bash
npm i -g vercel
vercel dev
```

This serves `web/index.html` at `/` and routes `/api/analyze`, `/api/check-action`, `/api/model`, and `/api/analysis/<id>` to the serverless functions in `api/`, which import the same `app.py` engine.

---

## 4. Verify the Build (Offline Fixtures)

One command, no Ollama, no network:

```bash
python3 scripts/run_offline_fixtures.py
```

This exercises the deterministic path end-to-end:

- Message/action fixtures through `analyze_content()` and `check_action()`
- Hidden-instruction variants (suppressed / invisible HTML text)
- Model-explanation citation validation (`validate_model_explanation()`)
- Async verdict behavior (`check_api_verdict_is_async()`)

All checks passing = the rules engine is healthy.

---

## 5. Optional — Local LLM Explanations (Ollama)

The rules verdict is deterministic and always available. Ollama adds an optional plain-language review layer:

```bash
# Install Ollama (https://ollama.com), then:
ollama pull qwen3.5:2b
python3 app.py
```

VIGIL auto-detects Ollama at `http://127.0.0.1:11434`. If the model is slow, unavailable, or its explanation fails citation validation, VIGIL **falls back to the deterministic explanation** — the demo never breaks.

Use a different model:

```bash
VIGIL_OLLAMA_MODEL=llama3.2:3b python3 app.py
```

---

## 6. Optional — Regenerate UI Design (Stitch)

Only needed when iterating on visual design:

```bash
npm install
npm run design:stitch
```

---

## 7. Deploy to Vercel

The repo ships with `vercel.json` (rewrites `/` → `web/` and `/api/*` → the Python functions):

```bash
vercel --prod
```

Or connect the GitHub repo in the Vercel dashboard — no build settings required.

---

## Quick Reference

```bash
# Full local stack in 3 commands
python3 app.py                              # 1. analyzer server (terminal 1)
python3 scripts/run_offline_fixtures.py     # 2. verify (terminal 2)
# 3. load extension/ via chrome://extensions
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Extension says it can't reach VIGIL | Is `python3 app.py` running? Extension requires port `8000` (see manifest note above). |
| `Address already in use` | Another process holds the port — use `VIGIL_PORT=<other> python3 app.py`. |
| Model review shows `offline` | Expected without Ollama — VIGIL uses the rules-only fallback automatically. |
| Web UI 404s on `/api/*` locally | Serve via `vercel dev`, not a static file server — the functions live in `api/`. |
