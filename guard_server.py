# guard_server.py — standalone agent-guard server (guide Steps 5 + 13).
# ThreadingHTTPServer so a slow /explain never blocks /guard.
# Run:  python3 guard_server.py          (default port 8000)
#       VIGIL_GUARD_PORT=8010 python3 guard_server.py
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import explain
from guard import guard

PORT = int(os.environ.get("VIGIL_GUARD_PORT", os.environ.get("VIGIL_PORT", "8000")))
HOST = os.environ.get("VIGIL_GUARD_HOST", "127.0.0.1")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        # CORS is not needed by the extension (background fetch is exempt), but
        # it lets browser demos and the web UI call the guard directly.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._send_json(400, {"error": "invalid_json"})

        if self.path == "/guard":
            result = guard(body.get("source"), body.get("action"))
            result["explanation"] = explain.fallback(result["decision"], result["evidence"])
            return self._send_json(200, result)

        if self.path == "/explain":
            return self._send_json(200, explain.explain(
                body.get("decision", "ALLOW"), body.get("evidence", [])))

        return self._send_json(404, {"error": "not_found"})

    def do_GET(self):
        if self.path == "/health":
            return self._send_json(200, {"ok": True, "service": "vigil-guard"})
        return self._send_json(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        print("[guard] %s" % (fmt % args))


if __name__ == "__main__":
    print("VIGIL guard listening on http://%s:%d" % (HOST, PORT))
    print("  POST /guard    -> instant rules verdict + template explanation")
    print("  POST /explain  -> grounded Ollama wording (rules fallback)")
    print("  GET  /health")
    explain.warm_up()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
