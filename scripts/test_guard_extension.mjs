// test_guard_extension.mjs — regression test for the guard extension's
// fail-closed contract, without needing a browser or a running server.
//
// background.js is loaded into a vm sandbox with stubbed `chrome` and `fetch`,
// then every transport failure mode is exercised. The contract under test:
// anything that is not a real decision object must resolve to DENY.
//
// Exit code 1 on any failure. No dependencies (node:fs / node:vm only).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import vm from "node:vm";

const root = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
const src = fs.readFileSync(path.join(root, "guard-extension", "background.js"), "utf8");

function runCase(name, fetchImpl, assert) {
  let listener = null;
  const sandbox = {
    chrome: { runtime: { onMessage: { addListener: (fn) => { listener = fn; } } } },
    fetch: fetchImpl,
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return new Promise((resolve) => {
    listener({ type: "VIGIL_GUARD", payload: {} }, null, (resp) => {
      const ok = assert(resp);
      console.log(
        (ok ? "PASS " : "FAIL ") + name +
        "  -> " + JSON.stringify({ decision: resp && resp.decision, tag: resp && resp.machine_tag })
      );
      resolve(ok);
    });
  });
}

const results = [];

results.push(await runCase(
  "unreachable guard fails closed",
  () => Promise.reject(new Error("connect ECONNREFUSED 127.0.0.1:8000")),
  (r) => r && r.decision === "DENY" && r.machine_tag === "VIGIL_UNREACHABLE"));

results.push(await runCase(
  "non-2xx response fails closed",
  () => Promise.resolve({ ok: false, status: 500 }),
  (r) => r && r.decision === "DENY" && r.machine_tag === "VIGIL_UNREACHABLE"));

results.push(await runCase(
  "response without a decision fails closed",
  () => Promise.resolve({ ok: true, json: () => Promise.resolve({ oops: true }) }),
  (r) => r && r.decision === "DENY" && r.machine_tag === "VIGIL_UNREACHABLE"));

results.push(await runCase(
  "non-JSON body fails closed",
  () => Promise.resolve({ ok: true, json: () => Promise.reject(new SyntaxError("bad json")) }),
  (r) => r && r.decision === "DENY" && r.machine_tag === "VIGIL_UNREACHABLE"));

results.push(await runCase(
  "a real verdict passes through untouched",
  () => Promise.resolve({ ok: true, json: () => Promise.resolve({ decision: "ALLOW", evidence: [] }) }),
  (r) => r && r.decision === "ALLOW" && r.machine_tag === undefined));

const fails = results.filter((x) => !x).length;
console.log("---");
console.log(`${results.length - fails}/${results.length} guard-extension checks pass`);
process.exit(fails ? 1 : 0);
