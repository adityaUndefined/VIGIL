#!/usr/bin/env bash
# e2e_run.sh — full end-to-end walkthrough runner (agent guard + demo page).
# Boots the guard server and a static server for demo/, runs the puppeteer
# walkthrough in scripts/e2e_demo.mjs, then cleans up both servers.
#
# Env:
#   PUPPETEER_MODULE  absolute path to a puppeteer install (when this repo has
#                     no node_modules with puppeteer)
#   HEADLESS          "0" to watch the browser
# Usage: sh scripts/e2e_run.sh
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

python3 guard_server.py >/tmp/vigil-e2e-guard.log 2>&1 &
GUARD_PID=$!
python3 -m http.server 9000 --bind 127.0.0.1 >/tmp/vigil-e2e-http.log 2>&1 &
HTTP_PID=$!
cleanup() { kill $GUARD_PID $HTTP_PID 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

for i in $(seq 1 40); do
  curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -sf http://127.0.0.1:8000/health >/dev/null; then
  echo "guard server failed to start:"; cat /tmp/vigil-e2e-guard.log; exit 2
fi
if ! curl -sf -o /dev/null http://127.0.0.1:9000/demo/hijack_demo.html; then
  echo "static server failed to start:"; cat /tmp/vigil-e2e-http.log; exit 2
fi
echo "servers up (guard pid $GUARD_PID, http pid $HTTP_PID)"
export GUARD_PID   # scripts/e2e_demo.mjs stops the server itself for the control case

if [ -n "${PUPPETEER_MODULE:-}" ]; then
  cd "$(dirname "$PUPPETEER_MODULE")/.."   # node resolves from the module tree
  node "$REPO/scripts/e2e_demo.mjs"
else
  node "$REPO/scripts/e2e_demo.mjs"
fi
