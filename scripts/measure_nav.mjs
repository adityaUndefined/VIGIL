// measure_nav.mjs — verify the header action-group layout on landing pages.
// Usage: node scripts/measure_nav.mjs <puppeteer-module-dir> <url> [widths...]
// For each viewport width, prints the rects of the header action elements and
// exits 1 if the theme toggle is not the rightmost element or the action
// group is not right-aligned to the nav's right padding edge.
import path from "node:path";
import url from "node:url";
import fs from "node:fs";

const repoRoot = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
const puppeteerDir = path.resolve(process.argv[2] || "/tmp/vigil-e2e/node_modules/puppeteer");
const target = process.argv[3] || "http://127.0.0.1:9000/web/index.html";
const widths = (process.argv[4] || "1280,900,700").split(",").map(Number);

const pkg = JSON.parse(fs.readFileSync(path.join(puppeteerDir, "package.json"), "utf8"));
const puppeteer = (await import(url.pathToFileURL(path.join(puppeteerDir, pkg.main)).href)).default;

// Serve the repo root statically so /web/index.html resolves.
const { spawn } = await import("node:child_process");
const httpd = spawn("python3", ["-m", "http.server", "9000", "--bind", "127.0.0.1"],
  { cwd: repoRoot, stdio: "ignore", detached: true });
const cleanup = () => { try { process.kill(-httpd.pid); } catch {} };
process.on("exit", cleanup);
for (let i = 0; i < 40; i++) {
  try { const r = await fetch(target); if (r.ok) break; } catch {}
  await new Promise((r) => setTimeout(r, 250));
}

const browser = await puppeteer.launch({
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

let failures = 0;
for (const width of widths) {
  const page = await browser.newPage();
  await page.setViewport({ width, height: 800 });
  await page.goto(target, { waitUntil: "load", timeout: 20000 });
  const m = await page.evaluate(() => {
    const rect = (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { left: +r.left.toFixed(1), right: +r.right.toFixed(1), visible: r.width > 0 };
    };
    const nav = document.querySelector("nav");
    const navRect = nav.getBoundingClientRect();
    const navStyle = getComputedStyle(nav);
    return {
      nav: { left: +navRect.left.toFixed(1), right: +navRect.right.toFixed(1),
             padRight: +navStyle.paddingRight.replace("px", "") },
      status: rect("#ollama-status"),
      launch: rect('a[href="/scanner.html"]'),
      toggle: rect("#theme-toggle"),
      viewport: window.innerWidth,
    };
  });
  const rightEdge = m.nav.right - m.nav.padRight;
  const parts = [];
  let fail = false;
  if (m.toggle && m.toggle.visible) {
    const isRightmost = m.launch ? m.toggle.right >= m.launch.right - 1 : true;
    parts.push(`toggle right=${m.toggle.right} rightmost=${isRightmost}`);
    if (!isRightmost) fail = true;
    const aligned = Math.abs(m.toggle.right - rightEdge) < 6;
    parts.push(`group flush with nav edge (edge=${rightEdge})=${aligned}`);
    if (!aligned) fail = true;
  }
  if (m.launch && m.launch.visible) {
    parts.push(`launch right=${m.launch.right}`);
  }
  console.log(`w=${width}: ${parts.join("; ")}`);
  if (fail) failures++;
  await page.close();
}

await browser.close();
cleanup();
console.log(failures ? `FAIL (${failures} widths)` : "PASS all widths");
process.exit(failures ? 1 : 0);
