// e2e_demo.mjs — end-to-end walkthrough of the agent guard (guide Step 8 demo).
// Loads guard-extension/ into real (headless) Chromium via puppeteer, opens
// demo/hijack_demo.html, and verifies the whole chain:
//   content script -> background.js -> POST /guard -> block card -> /explain.
//
// Prerequisites (run these first, from the repo root):
//   python3 guard_server.py &
//   python3 -m http.server 9000 &
//   npm i puppeteer   # any environment that has it; skipped in CI
//
// Env: EXT_DIR (default guard-extension), DEMO_URL, GUARD_URL, HEADLESS ("1").
// Exit code 1 on any failing check.
import fs from "node:fs";
import path from "node:path";
import url from "node:url";

// Puppeteer can come from a normal node_modules install or, when this repo
// has no node_modules, from an absolute path via PUPPETEER_MODULE.
let puppeteer;
try {
  puppeteer = (await import("puppeteer")).default;
} catch {
  const override = process.env.PUPPETEER_MODULE;
  if (!override) throw new Error("puppeteer not installed (npm i puppeteer) and PUPPETEER_MODULE not set");
  const pkg = JSON.parse(fs.readFileSync(path.join(override, "package.json"), "utf8"));
  const entry = path.join(override, pkg.main || "lib/cjs/puppeteer/puppeteer.js");
  puppeteer = (await import(url.pathToFileURL(entry).href)).default;
}

const root = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
const EXT = path.resolve(root, process.env.EXT_DIR || "guard-extension");
const DEMO = process.env.DEMO_URL || "http://127.0.0.1:9000/demo/hijack_demo.html";
const GUARD = process.env.GUARD_URL || "http://127.0.0.1:8000";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];

function check(name, ok, extra = "") {
  results.push(ok);
  console.log((ok ? "PASS " : "FAIL ") + name + (extra ? "  — " + extra : ""));
}

async function guardUp() {
  try {
    const r = await fetch(GUARD + "/health", { signal: AbortSignal.timeout(2000) });
    return r.ok;
  } catch { return false; }
}

async function newDemoPage(browser, url = DEMO) {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.log("  [pageerror]", e.message));
  await page.goto(url, { waitUntil: "load", timeout: 20000 });
  // content script must be live before we click. The dataset marker lives on
  // the shared DOM so it is visible from the page main world too.
  await page.waitForFunction(
    () => document.documentElement.dataset.vigilContent === "1",
    { timeout: 15000 });
  return page;
}

if (!fs.existsSync(path.join(EXT, "manifest.json"))) {
  console.error("Extension not found at " + EXT);
  process.exit(2);
}
if (!(await guardUp())) {
  console.error("Guard server not reachable at " + GUARD + " — start it first: python3 guard_server.py");
  process.exit(2);
}

const browser = await puppeteer.launch({
  headless: process.env.HEADLESS !== "0",
  args: [
    `--disable-extensions-except=${EXT}`,
    `--load-extension=${EXT}`,
    "--no-sandbox",
    "--disable-dev-shm-usage",
  ],
});

// 1. Manifest must have loaded the MV3 service worker.
let sw = null;
try {
  const t = await browser.waitForTarget(
    (t) => t.type() === "service_worker" && t.url().endsWith("background.js"),
    { timeout: 15000 });
  sw = await t.worker();
} catch { /* handled by the check below */ }
check("extension service worker loads (manifest valid)", !!sw);

// 2. Guard server UP: full hijack flow must be blocked.
const page = await newDemoPage(browser);
const before = await page.evaluate(() => document.documentElement.childElementCount);
await page.click("#run");
try {
  await page.waitForFunction(
    () => document.getElementById("out").textContent.includes("BLOCKED by VIGIL"),
    { timeout: 20000 });
  check("demo shows BLOCKED by VIGIL (guard server up)", true);
} catch {
  const out = await page.evaluate(() => document.getElementById("out").textContent);
  check("demo shows BLOCKED by VIGIL (guard server up)", false, JSON.stringify(out.slice(0, 200)));
}

const after = await page.evaluate(() => document.documentElement.childElementCount);
check("block card appended to document", after === before + 1, `children ${before} -> ${after}`);

// Step 14: /explain wording arrives afterwards.
try {
  await page.waitForFunction(
    () => document.getElementById("out").textContent.includes("[written by"),
    { timeout: 20000 });
  const text = await page.evaluate(() => document.getElementById("out").textContent);
  check("explanation upgraded via /explain", /\[written by (rules|local AI)\]/.test(text),
    JSON.stringify(text.slice(0, 220)));
} catch {
  check("explanation upgraded via /explain", false);
}
await page.close();

// 2b. Form-submit interception on the hijack page: DENY must cancel the submit.
const pageF = await newDemoPage(browser);
await pageF.click("#leak button[type=submit]");
await sleep(1500);   // guard answers, then either navigation or nothing
check("form submit blocked on hijack page (no navigation)",
  !pageF.url().includes("?"), pageF.url());
const formoutF = await pageF.evaluate(() => document.getElementById("formout").textContent);
check("form submit blocked on hijack page (form never processed)", formoutF === "",
  JSON.stringify(formoutF));
await pageF.close();

// 2c. Clean page: the same submit must go through (ALLOW path).
const pageC = await newDemoPage(browser, new URL("clean_form.html", DEMO).href);
await pageC.click("#leak button[type=submit]");
try {
  await pageC.waitForFunction(
    () => document.getElementById("formout").textContent.includes("Form submitted!"),
    { timeout: 15000 });
  check("clean form submits (ALLOW path)", true);
} catch {
  const formout = await pageC.evaluate(() => document.getElementById("formout").textContent);
  check("clean form submits (ALLOW path)", false, JSON.stringify(formout));
}
await pageC.close();

// 3. Guard server DOWN: control case — demo degrades to "Forwarded (!)".
console.log("  ...stopping guard server for the unreachable-control case");
let stopped = false;
if (process.env.GUARD_PID) {
  try { process.kill(Number(process.env.GUARD_PID), "SIGTERM"); stopped = true; }
  catch (e) { console.log("  kill failed:", e.message); }
} else {
  try {
    const { execSync } = await import("node:child_process");
    execSync("pkill -f 'guard_server.py' || true");
    stopped = true;
  } catch { stopped = false; }
}
for (let i = 0; i < 20 && (await guardUp()); i++) await sleep(250);
check("control: guard server stopped", stopped && !(await guardUp()));

const page2 = await newDemoPage(browser);
await page2.click("#run");
try {
  await page2.waitForFunction(
    () => document.getElementById("out").textContent.includes("Forwarded (!)"),
    { timeout: 20000 });
  check("control: guard unreachable -> demo 'forwards' (no block card)", true);
} catch {
  const out = await page2.evaluate(() => document.getElementById("out").textContent);
  check("control: guard unreachable -> demo 'forwards' (no block card)", false,
    JSON.stringify(out.slice(0, 200)));
}
await page2.close();

await browser.close();
const fails = results.filter((r) => !r).length;
console.log("---");
console.log(`${results.length - fails}/${results.length} e2e checks pass`);
process.exit(fails ? 1 : 0);
