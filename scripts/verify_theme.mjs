// verify_theme.mjs — dark-mode redesign verification (computed styles + WCAG).
// Usage: node scripts/verify_theme.mjs [puppeteer-module-dir]
// For each page (index, scanner, agent-guard, faqs) and each theme (dark,
// light): asserts the charcoal token system applies in dark, the light theme
// is unchanged, key text meets 4.5:1 contrast, and no surface is pure black.
// Saves screenshots to /tmp/vigil-shots/ for visual inspection.
import path from "node:path";
import url from "node:url";
import fs from "node:fs";
import { spawn } from "node:child_process";

const repoRoot = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
const puppeteerDir = path.resolve(process.argv[2] || "/tmp/vigil-e2e/node_modules/puppeteer");
const SHOTS = "/tmp/vigil-shots";
fs.mkdirSync(SHOTS, { recursive: true });

const pkg = JSON.parse(fs.readFileSync(path.join(puppeteerDir, "package.json"), "utf8"));
const puppeteer = (await import(url.pathToFileURL(path.join(puppeteerDir, pkg.main)).href)).default;

// Serve web/ as docroot on 9317 (absolute asset paths like /style.css then
// resolve as they do under app.py and Vercel; avoid clashing with the preview).
const PORT = 9317;
const httpd = spawn("python3", ["-m", "http.server", String(PORT), "--bind", "127.0.0.1"],
  { cwd: path.join(repoRoot, "web"), stdio: "ignore", detached: true });
const cleanup = () => { try { process.kill(-httpd.pid); } catch {} };
process.on("exit", cleanup);

const PAGES = ["index", "scanner", "agent-guard", "faqs"];
const results = [];

function check(name, ok, extra = "") {
  results.push(ok);
  console.log((ok ? "PASS " : "FAIL ") + name + (extra ? "  — " + extra : ""));
}

// WCAG relative luminance / contrast ratio.
function lum(rgb) {
  const f = (c) => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2]);
}
function contrast(fg, bg) {
  const l1 = lum(fg), l2 = lum(bg);
  return ((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05));
}
function parseColor(s) {
  if (!s) return null;
  const m = s.match(/rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)/);
  if (!m) return null;
  return [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]];
}
// Composite an rgba color over an opaque background color.
function over(fg, bg) {
  const a = fg[3];
  return [0, 1, 2].map((i) => Math.round(fg[i] * a + bg[i] * (1 - a)));
}

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });

for (const pageName of PAGES) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });

  // DARK
  await page.goto(`http://127.0.0.1:${PORT}/${pageName}.html`, { waitUntil: "networkidle0", timeout: 30000 });
  await page.evaluate(() => localStorage.setItem("vigil-theme", "dark"));
  await page.reload({ waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 400));

  const d = await page.evaluate(() => {
    const cs = (sel, prop) => {
      const el = document.querySelector(sel);
      return el ? getComputedStyle(el)[prop] : null;
    };
    const rootStyle = getComputedStyle(document.documentElement);
    return {
      theme: document.documentElement.dataset.theme,
      bodyBg: getComputedStyle(document.body).backgroundColor,
      pageVar: rootStyle.getPropertyValue("--page").trim(),
      surfaceVar: rootStyle.getPropertyValue("--surface").trim(),
      inkVar: rootStyle.getPropertyValue("--ink").trim(),
      headerBg: cs("header.sticky", "backgroundColor"),
      headerBorder: cs("header.sticky", "borderTopColor"),
      navLinkColor: cs("header.sticky .nav-link", "color"),
      heroLabelBg: cs(".hero-label", "backgroundColor"),
      heroAccent: cs(".hero-accent-word", "color"),
      cardBg: cs(".brutal-card", "backgroundColor"),
      statNumber: cs(".stat-number", "color"),
      statLabel: cs(".stat-label", "color"),
      consoleBg: cs(".console-card", "backgroundColor"),
      consoleText: cs(".console-text", "color"),
      heroTitleSize: cs(".hero-title", "fontSize"),
      dominantSize: cs(".hero-dominant", "fontSize"),
      metaTheme: document.querySelector('meta[name="theme-color"]')?.content,
    };
  });
  await page.screenshot({ path: `${SHOTS}/${pageName}-dark.png`, fullPage: false });

  check(`${pageName}: dark theme active`, d.theme === "dark");
  check(`${pageName}: page token is #0D0E0F`, d.pageVar.toLowerCase() === "#0d0e0f", d.pageVar);
  check(`${pageName}: surface token is #151718`, d.surfaceVar.toLowerCase() === "#151718", d.surfaceVar);
  check(`${pageName}: ink token is #F2F0E9`, d.inkVar.toLowerCase() === "#f2f0e9", d.inkVar);
  check(`${pageName}: body bg is charcoal #0D0E0F (not pure black)`,
    d.bodyBg.replace(/\s/g, "") === "rgb(13,14,15)", d.bodyBg);
  check(`${pageName}: navbar dark glass (not cream)`, d.headerBg && !d.headerBg.includes("243, 239, 230"), d.headerBg);
  check(`${pageName}: navbar border subtle`, d.headerBorder.includes("42, 45, 47"), d.headerBorder);
  check(`${pageName}: theme-color meta #0d0e0f`, (d.metaTheme || "").toLowerCase() === "#0d0e0f", d.metaTheme);

  if (pageName === "index") {
    check("index: hero accent is vermilion", d.heroAccent.includes("232, 96, 60"), d.heroAccent);
    check("index: dominant line larger than base", parseFloat(d.dominantSize) > parseFloat(d.heroTitleSize),
      `${d.dominantSize} vs ${d.heroTitleSize}`);
    check("index: hero label dark surface", d.heroLabelBg && !d.heroLabelBg.includes("255, 255, 255"), d.heroLabelBg);
  }
  if (pageName === "index") {
    check("index: console card dark surface", d.consoleBg && !d.consoleBg.includes("255, 255, 255"), d.consoleBg);
  }

  // WCAG contrast: text colors composited over their dark surfaces.
  const ink = [242, 240, 233], surface = [21, 23, 24], pageBg = [13, 14, 15];
  const navInk = parseColor(d.navLinkColor);
  const statNum = parseColor(d.statNumber);
  const statLab = parseColor(d.statLabel);
  const consText = parseColor(d.consoleText);
  if (pageName === "index") {
    check("index: nav links >= 4.5:1 on header glass",
      navInk && contrast(navInk, [26, 27, 28]) >= 4.5, navInk && contrast(navInk, [26, 27, 28]).toFixed(2));
    check("index: console text >= 4.5:1 on console bg",
      consText && contrast(consText, surface) >= 4.5, consText && contrast(consText, surface).toFixed(2));
    check("index: stat numbers >= 7:1 on strip", statNum && contrast(statNum, surface) >= 7,
      statNum && contrast(statNum, surface).toFixed(2));
    check("index: stat labels >= 4.5:1 on strip", statLab && contrast(statLab, surface) >= 4.5,
      statLab && contrast(statLab, surface).toFixed(2));
  }

  // LIGHT unchanged
  await page.evaluate(() => localStorage.setItem("vigil-theme", "light"));
  await page.reload({ waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 400));
  const l = await page.evaluate(() => ({
    theme: document.documentElement.dataset.theme,
    bodyBg: getComputedStyle(document.body).backgroundColor,
    pageVar: getComputedStyle(document.documentElement).getPropertyValue("--page").trim(),
    headerBg: getComputedStyle(document.querySelector("header.sticky")).backgroundColor,
  }));
  await page.screenshot({ path: `${SHOTS}/${pageName}-light.png`, fullPage: false });

  check(`${pageName}: light theme intact`, l.theme === "light" && l.pageVar.toLowerCase() === "#f3efe6",
    `${l.theme} ${l.pageVar}`);
  check(`${pageName}: light navbar still cream`, l.headerBg.includes("243, 239, 230"), l.headerBg);

  await page.close();
}

await browser.close();
cleanup();
const fails = results.filter((r) => !r).length;
console.log("---");
console.log(`${results.length - fails}/${results.length} theme checks pass — screenshots in ${SHOTS}`);
process.exit(fails ? 1 : 0);
