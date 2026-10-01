# VIGIL Agent Guard

A fail-closed policy gate that stops AI agents from falling for scams, prompt injection, and hidden instructions before they act.

## The contract

An AI agent may proceed with an action **only** when the guard response has `allowed: true`.

Everything else is a denial:

- `allowed: false` — the policy gate denied the action (the normal path for scams).
- `machine_tag: VIGIL_UNREACHABLE` — VIGIL could not be reached, so the gate **failed closed**. The agent must not act on unreviewed content.
- `machine_tag: GUARD_RESPONSE_INVALID` — the response could not be validated, fail closed.
- `machine_tag: UNKNOWN_ACTION` — the action name was not recognized, fail closed.

Agents should branch on `allowed` / `machine_tag`, never on prose. The `reason` field is for humans.

## What the gate denies

| Signal | Outcome |
|---|---|
| Hidden HTML instructions aimed at AI ("ignore previous instructions…") | DENY |
| Sensitive actions: `send_credentials`, `send_private_data`, `make_payment` (and the tool names `send_email`, `forward_email`, `submit_form`, `share_file`, `autofill`, `open_url`) | DENY |
| Links resolving through redirector/shortener services (`bit.ly`, `t.co`, …) | DENY |
| Any content that does not review as `ALLOW` (urgency, payment, credential requests, lookalike hosts, plain HTTP…) | DENY |
| Unrecognized action names | DENY (fail closed) |
| VIGIL unreachable / timeout / bad response | DENY (fail closed) |

Read-only actions (`navigate`, `summarize`, `read_page`) on ALLOW-reviewed content are the only path to `ALLOW`.

Action names are accepted in **both** vocabularies — the agent-facing names
above *and* the tool names used by `guard.py` and the guard extension — so an
agent is never denied merely for naming the same action differently.

## Why fail-closed matters

A permissive gate is worse than no gate: an attacker only needs VIGIL to be down, or a response to be malformed, to slip an action past it. VIGIL's agent guard inverts that: **if the safety check cannot complete, the answer is no.** The `VIGIL_UNREACHABLE` tag makes this explicit so agent code can distinguish "blocked by policy" from "could not verify" and log accordingly.

## Quick start

```bash
# 1. Start VIGIL — it serves both /api/guard (this client) and /guard
#    (the browser extension and demo pages), so one process is enough.
python3 app.py

# 2. Check an action before your agent takes it
python3 agent/vigil_agent_guard.py check "Reply with your OTP to restore access" --action send_credentials
# decision: DENY

# 3. Run the built-in behavior demo (6 scenarios, exit code 1 on deviation)
python3 agent/vigil_agent_guard.py demo
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `VIGIL_GUARD_URL` | `http://127.0.0.1:8000` | Analyzer base URL for the client |
| `VIGIL_HOST` / `VIGIL_PORT` | `127.0.0.1` / `8000` | Server bind address/port |
| `VIGIL_GUARD_PORT` / `VIGIL_GUARD_HOST` | `8010` / `127.0.0.1` | Optional standalone `guard_server.py` (never collides with `app.py`) |

## HTTP API

`app.py` serves **both** guard endpoints, so no second server is required:

- `POST /api/guard` — `{content, action, agent_id}` (this client, `agent/guarded.py`)
- `POST /guard`, `POST /explain`, `GET /health` — the standalone surface used by
  the Chromium guard extension and the demo pages

The optional standalone server (`guard_server.py`) serves the same `/guard`,
`/explain` and `/health` on port **8010** by default, so it can always run
alongside the analyzer.

```bash
curl -s -X POST http://127.0.0.1:8000/api/guard \
  -H 'Content-Type: application/json' \
  -d '{"content": "...", "action": "navigate", "agent_id": "my-agent"}'
```

Response (deterministic; no async model work, no polling):

```json
{
  "decision": "DENY",
  "allowed": false,
  "action": "navigate",
  "content_decision": "DENY",
  "reason": "Hidden instructions aim to control an AI agent; the action must not proceed.",
  "machine_tag": "DENIED_BY_GUARD",
  "evidence": [...],
  "explanation": {...},
  "policy": {"version": 1, "fail_closed": true, ...}
}
```

## Tool schema for function-calling agents

`agent/vigil-guard.tool.json` is a ready-made tool definition. Register it with your agent runtime and map the tool call to:

```python
from vigil_agent_guard import check_action
result = check_action(content, action)   # never raises
if not result["allowed"]:
    ...  # refuse, log machine_tag, surface reason to the user
```

## Testing

```bash
npm run fixtures         # deterministic engine fixtures, includes guard checks
npm run guard:fixtures   # offline guard fixtures (hidden text, provenance) — 5/5
npm run guard:smoke      # live /guard + /explain smoke test
npm run guard:extension  # extension fail-closed contract (no browser needed)
npm run guard:e2e        # full headless-Chromium walkthrough
npm run guard            # client demo against a live analyzer
npm run smoke            # live end-to-end checks, includes /api/guard
```
