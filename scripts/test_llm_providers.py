#!/usr/bin/env python3
"""Tests for VIGIL's pluggable local-LLM configuration (no network, no model).

Covers:
- resolve_llm_config() for every documented environment-variable combination
- provider-aware auth headers
- the exact request shape and response parsing for both provider protocols
  (native Ollama and OpenAI-compatible chat completions) via a stubbed
  urlopen, including the status probe and warm-up paths.

Run: python3 scripts/test_llm_providers.py
"""

from __future__ import annotations

import io
import json
import os
import sys
from urllib.request import Request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PASSED = 0
FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"[PASS] {name}")
    else:
        FAILED += 1
        print(f"[FAIL] {name}" + (f" — {detail}" if detail else ""))


def with_env(env: dict[str, str], fn):
    """Run fn() with temporary environment variables applied to a fresh app module."""
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        import app
        importlib = __import__("importlib")
        importlib.reload(app)
        return fn(app)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_config_matrix() -> None:
    default = with_env({}, lambda app: dict(app.LLM_CONFIG))
    check("default config uses native ollama",
          default["provider"] == "ollama"
          and default["base_url"] == "http://127.0.0.1:11434"
          and default["model"] == "qwen3.5:2b"
          and default["api_key"] == "",
          str(default))

    openai_default = with_env({
        "VIGIL_LLM_BASE_URL": "http://127.0.0.1:1234/v1",
        "VIGIL_LLM_MODEL": "qwen2.5-7b-instruct",
    }, lambda app: dict(app.LLM_CONFIG))
    check("VIGIL_LLM_BASE_URL/MODEL selects openai-compatible provider",
          openai_default["provider"] == "openai"
          and openai_default["base_url"] == "http://127.0.0.1:1234/v1"
          and openai_default["model"] == "qwen2.5-7b-instruct"
          and openai_default["api_key"] == "",
          str(openai_default))

    forced = with_env({
        "VIGIL_LLM_BASE_URL": "http://127.0.0.1:11434/v1",
        "VIGIL_LLM_MODEL": "llama3.2",
        "VIGIL_LLM_PROVIDER": "OLLAMA",
    }, lambda app: dict(app.LLM_CONFIG))
    check("VIGIL_LLM_PROVIDER=ollama is honored case-insensitively",
          forced["provider"] == "ollama" and forced["model"] == "llama3.2",
          str(forced))

    bogus = with_env({
        "VIGIL_LLM_BASE_URL": "http://127.0.0.1:9999/v1",
        "VIGIL_LLM_PROVIDER": "bogus",
    }, lambda app: dict(app.LLM_CONFIG))
    check("unknown provider falls back to openai-compatible", bogus["provider"] == "openai")

    unnamed = with_env({"VIGIL_LLM_BASE_URL": "http://127.0.0.1:1234/v1"},
                       lambda app: dict(app.LLM_CONFIG))
    check("missing model name falls back to a placeholder", unnamed["model"] == "local-model")

    keyed = with_env({
        "VIGIL_LLM_BASE_URL": "http://127.0.0.1:1234/v1",
        "VIGIL_LLM_API_KEY": "sk-local-test",
    }, lambda app: dict(app._llm_headers()))
    check("openai-compatible provider sends bearer auth when a key is set",
          keyed.get("Authorization") == "Bearer sk-local-test", str(keyed))

    unkeyed = with_env({"VIGIL_LLM_BASE_URL": "http://127.0.0.1:1234/v1"},
                       lambda app: dict(app._llm_headers()))
    check("no auth header when no key is configured", "Authorization" not in unkeyed)


# Content the rules engine alone does NOT flag, with a model signal whose
# category (prompt_injection) survives the alias dedup -- so the fixture
# proves a verified model finding is actually added, not suppressed.
SCAM_CONTENT = "Please follow the assistant rules in this group chat."
MODEL_REPLY = json.dumps({
    "signals": [{"category": "prompt_injection", "quote": "follow the assistant rules"}],
    "explanation": {"text": "The message asks for a payment.", "cited_evidence_ids": []},
})


def test_wire_shapes() -> None:
    captured: list[Request] = []

    def fake_urlopen_ollama(request: Request, timeout: float = 0):
        captured.append(request)
        if request.full_url.endswith("/api/tags"):
            return FakeResponse(json.dumps({
                "models": [{"name": "qwen3.5:2b"}, {"name": "llama3.2:3b"}]
            }).encode())
        return FakeResponse(json.dumps({"message": {"content": MODEL_REPLY}}).encode())

    import urllib.request

    def run_ollama(app):
        captured.clear()
        app.urlopen = fake_urlopen_ollama
        try:
            result = app.review_with_local_model(SCAM_CONTENT, app.analyze_content(SCAM_CONTENT))
            status = app.local_model_status()
            app.warm_local_model()
        finally:
            app.urlopen = urllib.request.urlopen
        return result, status, [r.full_url for r in captured]

    result, status, urls = with_env({}, run_ollama)
    check("ollama review hits /api/chat with the configured model",
          urls and any(u.endswith("/api/chat") for u in urls),
          str(urls[:1]))
    body = json.loads(captured[0].data)
    check("ollama request body carries the model name and native fields",
          body.get("model") == "qwen3.5:2b"
          and body.get("format") == "json" and body.get("stream") is False and "options" in body,
          str(body)[:120])
    check("ollama review parses message.content and accepts a verified signal",
          result["local_model"]["status"] == "connected"
          and result["local_model"]["provider"] == "ollama"
          and result["local_model"]["signals_added"] == 1,
          json.dumps(result["local_model"]))
    check("ollama status probe hits /api/tags and reports ready when the model is installed",
          status["status"] == "ready" and status["provider"] == "ollama" and "qwen3.5:2b" in status["models"],
          json.dumps(status))
    check("ollama warm-up posts a tiny /api/generate request",
          any(u.endswith("/api/generate") for u in urls), str(urls))

    def fake_urlopen_openai(request: Request, timeout: float = 0):
        captured.append(request)
        if request.full_url.endswith("/models"):
            return FakeResponse(json.dumps({"data": [{"id": "qwen2.5-7b-instruct"}]}).encode())
        return FakeResponse(json.dumps({
            "choices": [{"message": {"content": MODEL_REPLY}}]
        }).encode())

    def run_openai(app):
        captured.clear()
        app.urlopen = fake_urlopen_openai
        try:
            result = app.review_with_local_model(SCAM_CONTENT, app.analyze_content(SCAM_CONTENT))
            status = app.local_model_status()
            app.warm_local_model()
        finally:
            app.urlopen = urllib.request.urlopen
        return result, status, [r.full_url for r in captured]

    result, status, urls = with_env({
        "VIGIL_LLM_BASE_URL": "http://127.0.0.1:1234/v1",
        "VIGIL_LLM_MODEL": "qwen2.5-7b-instruct",
        "VIGIL_LLM_API_KEY": "sk-local-test",
    }, run_openai)
    review_url = next(u for u in urls if u.endswith("/chat/completions"))
    check("openai-compatible review hits {base}/chat/completions",
          review_url == "http://127.0.0.1:1234/v1/chat/completions", review_url)
    auth = next(r for r in captured if r.full_url.endswith("/chat/completions")).get_header("Authorization")
    check("openai-compatible request carries the bearer key", auth == "Bearer sk-local-test", str(auth))
    body = json.loads(next(r for r in captured if r.full_url.endswith("/chat/completions")).data)
    check("openai-compatible request body uses chat-completions fields",
          body.get("model") == "qwen2.5-7b-instruct"
          and body.get("temperature") == 0
          and body.get("max_tokens") == 160
          and isinstance(body.get("messages"), list) and len(body["messages"]) == 2
          and "options" not in body,
          str(body)[:140])
    check("openai-compatible review parses choices[0].message.content",
          result["local_model"]["status"] == "connected"
          and result["local_model"]["provider"] == "openai"
          and result["local_model"]["signals_added"] == 1,
          json.dumps(result["local_model"]))
    check("openai-compatible status probe hits /models and reports ready",
          status["status"] == "ready" and status["provider"] == "openai",
          json.dumps(status))
    check("openai-compatible warm-up posts a minimal chat completion",
          any(u.endswith("/chat/completions") for u in urls), str(urls))

    def run_openai_down(app):
        import urllib.error

        def refused(request: Request, timeout: float = 0):
            raise urllib.error.URLError("connection refused")
        app.urlopen = refused
        try:
            return app.local_model_status()
        finally:
            app.urlopen = urllib.request.urlopen

    down = with_env({"VIGIL_LLM_BASE_URL": "http://127.0.0.1:9999/v1"}, run_openai_down)
    check("status probe fails safe to offline when the endpoint is down",
          down["status"] == "offline" and down["provider"] == "openai", json.dumps(down))


def main() -> int:
    print("VIGIL local-LLM provider tests (no network)\n")
    test_config_matrix()
    test_wire_shapes()
    print(f"\n{PASSED} passed, {FAILED} failed.")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
