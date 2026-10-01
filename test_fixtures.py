#!/usr/bin/env python3
# test_fixtures.py — offline fixture runner (guide Step 6).
# Proves the deterministic path without Ollama or network:
#   python3 test_fixtures.py
# Exit code 1 on any FAIL, so CI can gate on it.
import glob
import json
import os
import sys

from guard import guard


def main():
    fixtures = sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "*.json")))
    if not fixtures:
        print("No fixtures found in fixtures/")
        return 1
    failures = 0
    for path in fixtures:
        with open(path, "r", encoding="utf-8") as f:
            fx = json.load(f)
        result = guard(fx.get("source"), fx.get("action"))
        ok = result["decision"] == fx["expected_decision"]
        if not ok:
            failures += 1
        print(("PASS" if ok else "FAIL"), fx["id"], result["decision"],
              [e["id"] for e in result["evidence"]],
              "latency=%sms" % result["latency_ms"])
    print("---")
    print("%d/%d pass" % (len(fixtures) - failures, len(fixtures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
