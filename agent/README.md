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
| Sensitive actions: `send_credentials`, `send_private_data`, `make_payment` | DENY |
| Links resolving through redirector/shortener services (`bit.ly`, `t.co`, …) | DENY |
| Any content that does not review as `ALLOW` (urgency, payment, credential requests, lookalike hosts, plain HTTP…) | DENY |
| Unrecognized action names | DENY (fail closed) |
| VIGIL unreachable / timeout / bad response | DENY (fail closed) |

Read-only actions (`navigate`, `summarize`, `read_page`) on ALLOW-reviewed content are the only path to `ALLOW`.

## Why fail-closed matters

A permissive gate is worse than no gate: an attacker only needs VIGIL to be down, or a response to be malformed, to slip an action past it. VIGIL's agent guard inverts that: **if the safety check cannot complete, the answer is no.** The `VIGIL_UNREACHABLE` tag makes this explicit so agent code can distinguish "blocked by policy" from "could not verify" and log accordingly.

## Quick start

```bash
# 1. Start the analyzer (or point at a running one)
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

## HTTP API

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
npm run fixtures   # deterministic engine fixtures, includes guard checks
npm run smoke      # live end-to-end checks, includes /api/guard
npm run guard      # client demo against a live analyzer
```
