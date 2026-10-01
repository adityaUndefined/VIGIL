# VIGIL — Build & Run Guide

Step-by-step instructions to build, run, and verify every component of VIGIL locally and in deployment.

## Project Components

| Component | Location | What it is |
|---|---|---|
| Analyzer server | `app.py` | Local Python HTTP server — the rules engine + optional Ollama review |
| Chromium extension | `extension/` | Minimal browser extension to review the current page |
| **VIGIL Security extension** | `vigil-extension/` | Production MV3 companion: side panel, page/URL/message/screenshot scans, history, settings — see `vigil-extension/README.md` |
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
- **A local LLM server** (optional) — Ollama, or any OpenAI-compatible server (LM Studio, llama.cpp, vLLM, Jan, LocalAI). VIGIL works fully without one.

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
| `VIGIL_LLM_BASE_URL` | _(unset)_ | Any OpenAI-compatible local server (see below) |
| `VIGIL_LLM_MODEL` | _(unset)_ | Model id your server exposes |
| `VIGIL_LLM_PROVIDER` | `openai` | `openai` or `ollama` (only used with `VIGIL_LLM_BASE_URL`) |
| `VIGIL_LLM_API_KEY` | _(unset)_ | Optional bearer key; most local servers need none |
| `VIGIL_OLLAMA_URL` | `http://127.0.0.1:11434` | Native Ollama endpoint (used when `VIGIL_LLM_BASE_URL` is unset) |
| `VIGIL_OLLAMA_MODEL` | `qwen3.5:2b` | Native Ollama model |

Example — run on a different port:

```bash
VIGIL_PORT=9000 python3 app.py
```

> ⚠️ The extension's `host_permissions` is pinned to `http://127.0.0.1:8000/*`. If you change the port, update `extension/manifest.json` to match.

---

## 2. Load the Chromium Extension

Two extensions ship in this repo:

- **`extension/`** — the original minimal page-review popup.
- **`vigil-extension/`** — the full **VIGIL Security** side-panel extension
  (Manifest V3): "Scan This Page", URL/message analysis, right-click
  "Scan with VIGIL", and **Capture & Scan** (VIGIL Vision with local OCR —
  screenshots never leave the device). It talks to the same analyzer server
  and needs no extra setup.

### Load VIGIL Security (recommended)

1. Start the local server first (step 1) — it talks to `http://127.0.0.1:8000`.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the `vigil-extension/` directory.
4. Pin **VIGIL Security** and click the icon to open the side panel.
5. Full instructions (API URL configuration, permissions, privacy, tests):
   [`vigil-extension/README.md`](vigil-extension/README.md).

### Load the minimal popup extension

1. `chrome://extensions` → **Load unpacked** → select `extension/`.
2. Pin "VIGIL Page Review" to the toolbar. Navigate to any page and click the icon to get an `ALLOW` / `WARN` / `DENY` review.

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

This serves `web/index.html` at `/` and routes `/api/analyze`, `/api/check-action`, `/api/guard`, `/api/model`, and `/api/analysis/<id>` to the serverless functions in `api/`, which import the same `app.py` engine. `/api/guard` and `/api/model` return synchronously with a rules-only verdict (no local-model polling on Vercel), and background analysis jobs live only in the running analyzer's memory — `/api/analysis/<id>` polling works against `python3 app.py`, not a fresh serverless instance.

> Security note: the local server binds to `127.0.0.1` by default. Setting `VIGIL_HOST=0.0.0.0` exposes the unauthenticated analyze/guard APIs to your network — do this only inside an isolated environment (the managed preview does exactly this).

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

## 5. Optional — Connect Your Own Local LLM

The rules verdict is deterministic and always available. A local LLM adds an optional plain-language review layer. **The decision is never made by the model** — it may only add evidence-backed warnings, and its output is verified against the source content before it is shown.

Two ways to connect a model — pick one, then follow the step-by-step procedure below.

| You already have… | Use |
|---|---|
| LM Studio, llama.cpp, vLLM, Jan, LocalAI, or any OpenAI-compatible server | **Option A** |
| Nothing installed yet, and you want the simplest path | **Option B** (Ollama) |

### Option A — Any OpenAI-compatible local server (recommended)

Works with **LM Studio, llama.cpp server (`llama-server`), vLLM, Jan, LocalAI, Ollama's OpenAI endpoint**, and anything else speaking the OpenAI chat-completions protocol.

First, start one of these servers so it serves a model:

```bash
# LM Studio: install from https://lmstudio.ai, download a model in the app,
# then start "Local Server" (Developer tab). Default: http://127.0.0.1:1234/v1

# llama.cpp server (serves a GGUF model you downloaded):
llama-server -m models/qwen2.5-7b-instruct-q4_k_m.gguf --port 8080
# -> http://127.0.0.1:8080/v1

# vLLM (GPU, serves any Hugging Face model):
vllm serve Qwen/Qwen2.5-7B-Instruct --port 8001
# -> http://127.0.0.1:8001/v1

# Ollama's OpenAI endpoint (already running Ollama? you already have it):
# -> http://127.0.0.1:11434/v1
```

Then point VIGIL at it:

```bash
# Example: LM Studio's local server
VIGIL_LLM_BASE_URL=http://127.0.0.1:1234/v1 \
VIGIL_LLM_MODEL=qwen2.5-7b-instruct \
python3 app.py

# Example: llama.cpp server
VIGIL_LLM_BASE_URL=http://127.0.0.1:8080/v1 \
VIGIL_LLM_MODEL=qwen2.5-7b-instruct-q4_k_m.gguf \
python3 app.py

# If your server needs a key (rare for local use):
VIGIL_LLM_API_KEY=sk-local-... python3 app.py
```

> Tip: `VIGIL_LLM_MODEL` must match the model id your server exposes — LM Studio shows it in the server tab, llama.cpp uses the file name you passed, vLLM uses the repo id. `GET {BASE_URL}/models` lists them.

### Option B — Native Ollama (default, zero config)

```bash
# Install Ollama (https://ollama.com), then serve a model:
ollama pull qwen3.5:2b          # downloads the model
ollama serve                    # serves it at http://127.0.0.1:11434
python3 app.py                  # VIGIL auto-detects it
```

Use a different model:

```bash
VIGIL_OLLAMA_MODEL=llama3.2:3b python3 app.py
```

Point the Ollama variables at any host running Ollama (e.g. `VIGIL_OLLAMA_URL=http://192.168.1.20:11434`).

### Step-by-step: connect your local model

Follow these in order. Steps 1–2 are the only ones that differ between Option A and Option B.

**1. Start your model server so it is serving a model.**

```bash
# Option A — any OpenAI-compatible server
# LM Studio: open the app → download a model → Developer tab → Start Server
#   -> http://127.0.0.1:1234/v1
llama-server -m models/qwen2.5-7b-instruct-q4_k_m.gguf --port 8080   # -> :8080/v1

# Option B — Ollama
ollama serve        # -> http://127.0.0.1:11434
ollama pull qwen3.5:2b
```

Confirm the model is actually listed before touching VIGIL:

```bash
curl -s http://127.0.0.1:1234/v1/models     # Option A (use your own base URL)
curl -s http://127.0.0.1:11434/api/tags     # Option B
```

The id shown here is exactly what `VIGIL_LLM_MODEL` must contain.

**2. Tell VIGIL where the model is.**

Either export the variables, or write them into a `.env` file next to `app.py` (the server loads `.env`, and `.env.local` overrides it):

```bash
# Option A — OpenAI-compatible server
VIGIL_LLM_BASE_URL=http://127.0.0.1:1234/v1 \
VIGIL_LLM_MODEL=qwen2.5-7b-instruct \
python3 app.py
```

```bash
# .env  (same directory as app.py; restart the server after editing)
VIGIL_LLM_BASE_URL=http://127.0.0.1:1234/v1
VIGIL_LLM_MODEL=qwen2.5-7b-instruct
VIGIL_LLM_PROVIDER=openai
# VIGIL_LLM_API_KEY=sk-local-...    # only if your server requires a key
```

For Option B (Ollama) you normally need nothing at all — VIGIL defaults to `http://127.0.0.1:11434` with model `qwen3.5:2b`. Override only if you changed either:

```bash
VIGIL_OLLAMA_URL=http://127.0.0.1:11434 \
VIGIL_OLLAMA_MODEL=qwen3.5:2b \
python3 app.py
```

**3. Restart the server.** Environment variables are read at startup, so an already-running `app.py` will not pick up new values.

**4. Verify the connection** (next section).

### Verify the connection

```bash
# 1. The server's view of the local model
curl -s http://127.0.0.1:8000/api/model
# -> {"status": "ready", ...}   or a reason it is not ready

# 2. Offline protocol/config checks (no model or network needed)
npm run test:llm                 # 19 checks

# 3. Full walkthrough with mock local servers — no install required
npm run demo:llm
```

In the web UI the topbar shows the live state, e.g. `LOCAL MODEL READY · qwen2.5-7b-instruct · OPENAI-COMPATIBLE`. If the model is unreachable the badge says so and analysis still works — the verdict never depends on the model.

The agent guard's grounded explainer (`POST /explain`) uses the **same** Ollama settings (`VIGIL_OLLAMA_URL` / `VIGIL_OLLAMA_MODEL`), so pointing VIGIL at a remote Ollama also moves the guard's wording.

### Troubleshooting the local LLM

| Symptom | Cause | Fix |
|---|---|---|
| Topbar stays `RULES ONLY`, `/api/model` not ready | The model server is not running, or VIGIL was started before it | Start the server first, then restart `app.py` |
| `404` from `{BASE_URL}/models` | Wrong base URL — the `/v1` suffix is missing | `VIGIL_LLM_BASE_URL` must include `/v1` for OpenAI-compatible servers |
| `model not found` in the server's log | `VIGIL_LLM_MODEL` does not match the server's id | Use the id from `GET {BASE_URL}/models` verbatim (llama.cpp uses the file name) |
| Explanations stay templated | The model's answer failed citation validation, or it is too slow | Expected fallback — the verdict is unaffected. Try a smaller/faster model or a longer `VIGIL_LLM_*` timeout |
| `401` / `403` | The server requires a key | Set `VIGIL_LLM_API_KEY` |
| Ollama reachable from the shell but not from VIGIL | `VIGIL_OLLAMA_URL` still points at `127.0.0.1` from a container | Point it at the host that runs Ollama (e.g. `http://192.168.1.20:11434`) |
| Very slow first answer | The model is being loaded into memory | The first call warms it; subsequent calls reuse it (`keep_alive` is set) |

### Behavior and safety

- The topbar status shows what is connected, e.g. `LOCAL MODEL READY · qwen2.5-7b-instruct · OPENAI-COMPATIBLE`.
- If the model is slow, unavailable, or its explanation fails citation validation, VIGIL **falls back to the deterministic explanation** — the demo never breaks.
- Verify your wiring without a model: `npm run test:llm` (19 protocol/config checks, no network).
- See the whole journey live: `npm run demo:llm` (mock local servers + real VIGIL instances; no install).

> Privacy note: content is sent only to the endpoint **you** configured, on your machine or network. Nothing is sent to any cloud service.

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
                                            #    also serves /guard, /explain, /health
python3 scripts/run_offline_fixtures.py     # 2. verify (terminal 2)
# 3. load extension/ via chrome://extensions
```

```bash
# Agent guard — all of these talk to the app.py already running on :8000
python3 agent/vigil_agent_guard.py demo                    # 6 behavior scenarios
python3 agent/vigil_agent_guard.py check "Reply with your OTP" --action send_credentials
python3 test_fixtures.py                                   # offline guard fixtures (5/5)
python3 scripts/run_guard_smoke.py                         # live /guard, /explain smoke test
python3 guard_server.py                                    # OPTIONAL isolated guard on :8010
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Extension says it can't reach VIGIL | Is `python3 app.py` running? Extension requires port `8000` (see manifest note above). |
| `Address already in use` | Another process holds the port — use `VIGIL_PORT=<other> python3 app.py`. |
| Model review shows `offline` | Expected without a local LLM — rules-only fallback is automatic. Connect one via `VIGIL_LLM_BASE_URL`/`VIGIL_LLM_MODEL` (OpenAI-compatible) or `VIGIL_OLLAMA_URL`/`VIGIL_OLLAMA_MODEL` (Ollama) — see § 5. |
| Agent guard blocks with `VIGIL_UNREACHABLE` | It cannot reach `:8000` — start `python3 app.py`. Failing closed is intended, not a bug. |
| `guard_server.py` fails: `Address already in use` | `app.py` already serves `/guard` on `:8000`; the standalone server defaults to `:8010`. Change it with `VIGIL_GUARD_PORT`. |
| Guard answers `UNKNOWN_ACTION` | The action name is not recognized, so it fails closed. Use a name from `agent/README.md` (`navigate`, `summarize`, `read_page`, `send_credentials`, `send_private_data`, `make_payment`, or the tool names `forward_email`, `send_email`, `submit_form`, `share_file`, `autofill`, `open_url`). |
| Web UI 404s on `/api/*` locally | Serve via `vercel dev`, not a static file server — the functions live in `api/`. |
