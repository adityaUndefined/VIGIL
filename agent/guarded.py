# agent/guarded.py — wrap any Python agent tool call with the VIGIL guard
# (guide Step 9). This is also all a `vigil.check` MCP tool needs to call.
import json
import urllib.request

GUARD_URL = "http://127.0.0.1:8000/guard"


def guarded(run_tool, tool, args, source_html=None):
    """Consult POST /guard before running `tool`. DENY never reaches run_tool."""
    payload = {
        "source": {"html": source_html} if source_html else {},
        "action": {"tool": tool, "args": args},
    }
    req = urllib.request.Request(
        GUARD_URL,
        json.dumps(payload).encode(),
        {"Content-Type": "application/json"},
    )
    try:
        verdict = json.loads(urllib.request.urlopen(req, timeout=2).read())
    except Exception:
        # fail closed: if the guard cannot be consulted, do not act
        return {"blocked": True, "evidence": [{"id": "GUARD-UNREACHABLE",
                                               "signal": "The guard could not be consulted, so the action was refused.",
                                               "severity": "critical"}]}
    if verdict.get("decision") == "DENY":
        return {"blocked": True, "evidence": verdict.get("evidence", [])}
    return run_tool(**args)
