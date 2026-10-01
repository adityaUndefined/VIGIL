# VIGIL Security — Test Checklist

Prerequisite: backend running (`python3 app.py` → `http://127.0.0.1:8000`).

Automated coverage (already run, all passing):

- `node --check` on every extension JS file — syntax OK
- `node scripts/smoke_sidepanel.mjs` — 39 DOM checks against the real panel
  files + live backend (boot, health, phishing/safe/URL scans, history,
  settings, backend-down error, Try Again)
- Extractor unit test on `tests/fixtures/sample_page.html` — extraction + privacy
  (no input values leaked)
- Live endpoint checks — `/api/analyze` (message/URL/page content),
  `/api/vision/analyze`, `/api/analysis/<id>` polling, `/api/health`,
  backend-down behavior

## Load into Chrome

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select `vigil-extension/`.
3. Expect: no errors on the VIGIL card; service worker shows "Inactive"
   until first use, then runs without errors (click **service worker** to view its console).

## Manual matrix

| # | Test | Steps | Expected |
|---|---|---|---|
| 1 | Normal safe website | Open `tests/fixtures/test_page_safe.html` (or any benign site) → VIGIL → **Scan This Page** | SAFE banner, "No significant threats detected.", checks list |
| 2 | Suspicious URL | VIGIL → **Analyze Text** → `http://paypa1-alert-secure.example.com/login` | Warning/High Risk with URL indicator |
| 3 | Phishing-like message | **Analyze Text** → "Your account will be suspended. Verify immediately…" | High Risk, urgency + credential indicators |
| 4 | Login page | Open `tests/fixtures/test_page_suspicious.html` → **Scan This Page** | High Risk; form summary shows `masked` input type, never values |
| 5 | Screenshot w/ suspicious text | Open page 4, make it visible → **Capture & Scan** | Loading steps run locally (OCR/QR), then backend Vision verdict (DENY/70 style) |
| 6 | Screenshot w/ normal text | Capture page 1 | SAFE, "No significant threats detected." |
| 7 | Long webpage | Scan a very long article | Truncation note from backend appears if >200k chars; no hang |
| 8 | Many links | Scan any large portal | Link summary included; result still fast |
| 9 | No readable text | Open `chrome://version` → attempt scan | "VIGIL couldn't analyze this page." (restricted-page path) |
| 10 | Backend unavailable | Stop `app.py` → scan | "Unable to connect to VIGIL…" + **Try Again**; header shows Offline |
| 11 | Context menu | Select text on any page → right-click | "Scan with VIGIL" opens panel + scans selection |
| 12 | History | After several scans → 🕘 | Rows show time, source/type, risk pill; **Clear** empties |
| 13 | Settings toggles | ⚙ → toggle Page scanning off | Scan button disabled on Home; re-enable restores |
| 14 | Responsive | Resize the panel narrow (drag edge) | Content reflows; buttons stack; nothing overflows |

## QA pass criteria

- No console errors in: service worker console, panel console (Inspect views
  via `chrome://extensions` → VIGIL → *service worker* / *side panel*).
- No unhandled promise rejections in either console.
- Network tab shows requests **only** while a scan is running (never on idle).
- No API secrets anywhere in `vigil-extension/` (grep for "key", "token" —
  only backend-side config exists, none ships in the extension).
- Keyboard: Tab reaches every control; focus ring visible; Enter/Space
  activate buttons.
