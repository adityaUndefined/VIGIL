#!/usr/bin/env python3
"""Demo: connect VIGIL to your own local LLM — no real model required.

This script simulates the full user journey:

1. Starts two mock *local LLM servers* — one speaking the OpenAI-compatible
   protocol (what LM Studio, llama.cpp server, vLLM, Jan, and LocalAI expose)
   and one speaking native Ollama — on your machine.
2. Starts real VIGIL analyzer instances configured with the documented
   environment variables, exactly as a user would.
3. Sends content through the live endpoints and shows the model status,
   the model's verified advisory signals, and the fail-safe behavior when
   the LLM goes away.

Everything is standard library only and nothing leaves your machine.
Run:  python3 scripts/demo_local_llm.py   (or: npm run demo:llm)
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

LLM_PORT_OPENAI = 12340
LLM_PORT_OLLAMA = 12341
VIGIL_PORT_A = 8301
VIGIL_PORT_B = 8302

CLEAN_MESSAGE = "Hi Mira, the project review is at 3 PM in Room 204."
PHISHING_MESSAGE = (
    "SBI customer: your UPI KYC expires today. Verify immediately by replying "
    "with your OTP or your account will be blocked. https://sbi-kyc.example/verify"
)
# Rules engine sees nothing wrong here - the local model is what catches it.
DEAN_MESSAGE = "Message from the Dean's Office: confirm your library account today."


def section(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def step(text: str) -> None:
    print(f"\n  {text}")


# --------------------------------------------------------------------------
# Mock local-LLM servers
# --------------------------------------------------------------------------

def build_model_reply(content: str) -> str:
    """A tiny stand-in for a real local model: verbatim quotes only."""
    low = content.lower()
    signals = []
    explanation = "No additional findings. The message looks routine."
    if "dean" in low:
        signals.append({"category": "authority", "quote": "Message from the Dean's Office"})
        explanation = "Claims authority from a campus office. Verify through a channel you already trust."
    elif "expires today" in low:
        signals.append({"category": "urgency", "quote": "expires today"})
        explanation = "Uses deadline pressure to rush a decision. Confirm before acting."
    return json.dumps({
        "signals": signals,
        "explanation": {"text": explanation, "cited_evidence_ids": []},
    })


class MockLLMHandler(BaseHTTPRequestHandler):
    mode = "openai"       # "openai" | "ollama"
    requests_seen: list = []

    def _log(self, path: str, body: dict):
        content = ""
        try:
            messages = body.get("messages", [])
            user = next((m for m in messages if m.get("role") == "user"), {})
            inner = json.loads(user.get("content", "{}"))
            content = inner.get("content", "")[:48]
        except Exception:
            content = "?"
        self.requests_seen.append((path, content))

    def _json(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.mode == "openai" and self.path.endswith("/models"):
            self._json({"data": [{"id": "qwen2.5-7b-instruct"}]})
        elif self.mode == "ollama" and self.path.endswith("/api/tags"):
            self._json({"models": [{"name": "llama3.2:3b"}]})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self._log(self.path, body)
        if self.mode == "openai" and self.path.endswith("/chat/completions"):
            self._json({"choices": [{"message": {"content": build_model_reply(_content_of(body))}}]})
        elif self.mode == "ollama" and self.path.endswith("/api/chat"):
            self._json({"message": {"content": build_model_reply(_content_of(body))}})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *args):  # silence default request logging
        pass


def _content_of(body: dict) -> str:
    try:
        user = next(m for m in body["messages"] if m["role"] == "user")
        return json.loads(user["content"])["content"]
    except Exception:
        return ""


def start_mock_llm(mode: str, port: int):
    handler = type(f"Mock_{mode}", (MockLLMHandler,), {"mode": mode, "requests_seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler.requests_seen


# --------------------------------------------------------------------------
# VIGIL instance helpers
# --------------------------------------------------------------------------

LLM_ENV_KEYS = (
    "VIGIL_LLM_BASE_URL", "VIGIL_LLM_MODEL", "VIGIL_LLM_PROVIDER", "VIGIL_LLM_API_KEY",
    "VIGIL_OLLAMA_URL", "VIGIL_OLLAMA_MODEL",
)


def start_vigil(env: dict[str, str], port: int):
    # Each instance starts from a clean LLM environment, exactly like a fresh
    # user shell: VIGIL_LLM_* intentionally takes precedence over VIGIL_OLLAMA_*.
    for key in LLM_ENV_KEYS:
        os.environ.pop(key, None)
    for key, value in env.items():
        os.environ[key] = value
    import app
    importlib.reload(app)
    app.Handler.log_message = lambda *args, **kwargs: None
    server = ThreadingHTTPServer(("127.0.0.1", port), app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.05)
    return server


def api(port: int, path: str, payload: dict | None = None) -> dict:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"} if payload is not None else {},
        method="POST" if payload is not None else "GET",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())


def poll_analysis(port: int, analysis_id: str, seconds: float = 8.0) -> dict:
    deadline = time.time() + seconds
    while time.time() < deadline:
        job = api(port, f"/api/analysis/{analysis_id}")
        if job.get("status") == "complete":
            return job["result"]
        time.sleep(0.1)
    raise TimeoutError("model review did not finish")


def show(model: dict) -> None:
    local = model.get("local_model", {})
    print(f"     decision      : {model['decision']}")
    print(f"     rule evidence : {[e['type'] for e in model['evidence']]}")
    print(f"     local model   : {local.get('status')} · provider={local.get('provider')}"
          f" · name={local.get('name')}")
    v = local.get("verification", {})
    print(f"     verification  : {v.get('status')} (checked {v.get('checked')},"
          f" verified {v.get('verified')}, rejected {v.get('rejected')})")
    print(f"     explanation   : {model['explanation'].get('text', '')[:90]}")
    if local.get("signals"):
        for s in local["signals"]:
            print(f"     model signal  : {s['category']} — quoted: “{s['quote']}”")


# --------------------------------------------------------------------------
# The demo
# --------------------------------------------------------------------------

def main() -> int:
    print("VIGIL — connect your own local LLM (live demo, no model install needed)")

    section("STEP 1 · Start a local LLM server (what LM Studio / Ollama do)")
    openai_server, openai_log = start_mock_llm("openai", LLM_PORT_OPENAI)
    ollama_server, ollama_log = start_mock_llm("ollama", LLM_PORT_OLLAMA)
    print(f"  mock OpenAI-compatible server : http://127.0.0.1:{LLM_PORT_OPENAI}/v1"
          f"   (model: qwen2.5-7b-instruct)")
    print(f"  mock native Ollama server     : http://127.0.0.1:{LLM_PORT_OLLAMA}"
          f"   (model: llama3.2:3b)")

    section("STEP 2 · Point VIGIL at YOUR server (the only configuration needed)")
    print(f"""  A user with LM Studio / llama.cpp / vLLM / Jan runs:

      VIGIL_LLM_BASE_URL=http://127.0.0.1:{LLM_PORT_OPENAI}/v1 \\
      VIGIL_LLM_MODEL=qwen2.5-7b-instruct \\
      python3 app.py

  (Ollama users skip straight to STEP 5 — nothing to configure.)""")
    start_vigil({
        "VIGIL_LLM_BASE_URL": f"http://127.0.0.1:{LLM_PORT_OPENAI}/v1",
        "VIGIL_LLM_MODEL": "qwen2.5-7b-instruct",
    }, VIGIL_PORT_A)
    print(f"  VIGIL is live on http://127.0.0.1:{VIGIL_PORT_A} with that model wired in.")

    status = api(VIGIL_PORT_A, "/api/model")
    print(f"\n  GET /api/model ->\n     {json.dumps(status)}")
    print("  UI topbar shows: LOCAL MODEL READY · qwen2.5-7b-instruct · OPENAI-COMPATIBLE")

    section("STEP 3 · Every review now consults YOUR model (advisory only)")
    print("\n  a) Clean message — model agrees with the rules:")
    result = api(VIGIL_PORT_A, "/api/analyze", {"content": CLEAN_MESSAGE})
    show(poll_analysis(VIGIL_PORT_A, result["analysis_id"]))

    print("\n  b) Phishing message — rules DENY, model adds the plain-language review:")
    result = api(VIGIL_PORT_A, "/api/analyze", {"content": PHISHING_MESSAGE})
    show(poll_analysis(VIGIL_PORT_A, result["analysis_id"]))

    print("\n  c) The model's real value — a warning the rules alone would miss:")
    print("     content: \"Message from the Dean's Office: confirm your library account today.\"")
    result = api(VIGIL_PORT_A, "/api/analyze", {"content": DEAN_MESSAGE})
    print(f"     instant rules verdict sent to the UI: {result['decision']} (model still checking)")
    final = poll_analysis(VIGIL_PORT_A, result["analysis_id"])
    show(final)
    print("     -> ALLOW upgraded to WARN by a verbatim-quoted, independently verified finding.")

    print(f"\n  What YOUR server received (content goes only to the endpoint you chose):")
    for path, content in openai_log:
        print(f"     POST {path:<22} content=\"{content}...\"")

    section("STEP 4 · Fail-safe: shut the LLM off — VIGIL keeps protecting")
    openai_server.shutdown()
    openai_server.server_close()  # release the port so connections are refused instantly
    result = api(VIGIL_PORT_A, "/api/analyze", {"content": CLEAN_MESSAGE})
    show(poll_analysis(VIGIL_PORT_A, result["analysis_id"]))
    print("     -> verdict still instant and deterministic; the model layer simply goes quiet.")

    section("STEP 5 · Native Ollama users (zero config path)")
    start_vigil({
        "VIGIL_OLLAMA_URL": f"http://127.0.0.1:{LLM_PORT_OLLAMA}",
        "VIGIL_OLLAMA_MODEL": "llama3.2:3b",
    }, VIGIL_PORT_B)
    status = api(VIGIL_PORT_B, "/api/model")
    print(f"  GET /api/model -> {json.dumps(status)}")
    result = api(VIGIL_PORT_B, "/api/analyze", {"content": DEAN_MESSAGE})
    show(poll_analysis(VIGIL_PORT_B, result["analysis_id"]))
    ollama_server.shutdown()
    ollama_server.server_close()

    section("HOW TO RUN THIS FOR REAL")
    print("""  # OpenAI-compatible (LM Studio, llama.cpp server, vLLM, Jan, LocalAI)
  VIGIL_LLM_BASE_URL=http://127.0.0.1:1234/v1 VIGIL_LLM_MODEL=<your-model> python3 app.py

  # Native Ollama (https://ollama.com)
  ollama pull qwen3.5:2b && python3 app.py          # auto-detected defaults
  VIGIL_OLLAMA_MODEL=llama3.2:3b python3 app.py     # pick another model

  Verify your wiring without a model:  npm run test:llm
  Docs: BUILD.md § 5""")

    print("\nDemo finished — nothing was installed, nothing left your machine.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nDemo interrupted.")
        raise SystemExit(130)
