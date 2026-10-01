# VIGIL Security — Chrome Extension

**AI-powered protection against phishing, scams and suspicious websites.**

VIGIL Security is a Manifest V3 browser companion for the VIGIL cybersecurity
platform. It puts VIGIL's analysis engine one click away: scan the page you're
on, check a suspicious message, or run VIGIL Vision on a screenshot. All
detection happens in your VIGIL backend — the extension is a client, never a
second detection engine.

```
┌────────────────────────────────────────────────────────────┐
│  VIGIL                                        🕘  ⚙        │
│  AI Security Companion                                     │
│  ● Operational                                             │
│                                                            │
│  CURRENT PAGE                                              │
│  Account Verification Required                             │
│  https://example-login-security.com/…                      │
│  [ Scan This Page ]                                        │
│  [ Capture & Scan ]  [ Analyze Text ]                      │
└────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | What it does |
|---|---|
| **Side panel** | Click the VIGIL toolbar icon to open a persistent security panel next to any page. |
| **Scan This Page** | Extracts the page's URL, title, visible text, links, form *structure*, and login-field presence, then sends it to the VIGIL backend (`POST /api/analyze`). |
| **URL / message analysis** | "Analyze Text" (and the context menu) send content to the same `/api/analyze` endpoint the VIGIL web app uses. |
| **Scan with VIGIL** (right-click) | Highlight text anywhere → right-click → *Scan with VIGIL* → the side panel opens and scans the selection. |
| **Capture & Scan (VIGIL Vision)** | Captures the visible tab, runs **local** OCR (Tesseract.js) + QR decode (jsQR) + input-box detection in the panel, then posts the derived JSON to the existing `POST /api/vision/analyze`. **No image bytes leave your device.** |
| **Consistent result card** | Risk level, backend score (Vision), confidence, indicators with severity, and "Why VIGIL flagged this" — all from backend evidence. |
| **Scan history** | Metadata only (time, source, risk). Stored in `chrome.storage.local`; page text is never saved. |
| **Settings** | Toggle page scanning, clear history, backend status, optional per-site access. |

---

## 1. Run the VIGIL backend

The extension needs the VIGIL analyzer server:

```bash
cd VIGIL
python3 app.py          # serves http://127.0.0.1:8000
```

No `pip install` is needed — the analyzer uses only the Python standard
library. Verify: open `http://127.0.0.1:8000/api/health` → `{"ok": true, ...}`.

---

## 2. Load the extension into Chrome

1. Start the VIGIL server (step 1).
2. Open `chrome://extensions`.
3. Enable **Developer mode** (toggle, top right).
4. Click **Load unpacked**.
5. Select the `vigil-extension/` folder of this repo.
6. Pin **VIGIL Security** to the toolbar and click it — the side panel opens.

Works in any Chromium browser (Chrome, Edge, Brave). Requires Chrome 114+
(side panel API).

---

## 3. Configuring the API URL

Open `config/config.js` and set the backend address:

```js
API_BASE_URL: 'http://127.0.0.1:8000',
```

**Pointing at a remote/deployed backend?** Manifest V3 requires fetch hosts to
be declared in the manifest. Update `manifest.json`:

```json
"host_permissions": [
  "http://127.0.0.1:8000/*",
  "https://your-vigil-server.example.com/*"
]
```

Then reload the extension at `chrome://extensions` (↻ on the VIGIL card).

> **Note on HTTPS:** Chrome requires a **secure (https://)** host for
> `host_permissions` in production builds. If your backend runs plain HTTP on
> a LAN address, keep using the local server or put an https proxy in front.
> The VIGIL serverless deployment (`api/` functions on Vercel, e.g.
> `https://vigil-jet-three.vercel.app`) works out of the box.

No API keys or secrets live in the extension. The backend holds any LLM
credentials (Gemini/Ollama config) server-side; the extension only talks to
VIGIL's own endpoints.

---

## Permissions & privacy

| Permission | Why it's needed |
|---|---|
| `sidePanel` | The VIGIL side panel UI. |
| `contextMenus` | Adds "Scan with VIGIL" for selected text. |
| `storage` | Settings + metadata-only scan history (local only). |
| `activeTab` + `scripting` | Read page content **only when you click "Scan This Page"**, and capture the visible tab only when you click "Capture & Scan". |
| `host_permissions: http://127.0.0.1:8000/*` | Talk to the VIGIL backend. |
| `optional_host_permissions` | Lets you grant per-site access from Settings if a page blocks injection — requested explicitly, never silently. |

**VIGIL never collects:** passwords, credit-card numbers, authentication
tokens, keystrokes, or form values. Page extraction reads structure only
(input *types*, not values). Screenshots are analyzed locally by the OCR
engine; only extracted text regions and geometry are sent to the backend.
All scans are user-initiated — nothing is analyzed or transmitted
automatically.

---

## Project structure

```
vigil-extension/
├── manifest.json               # MV3 manifest
├── config/config.js            # API_BASE_URL + limits (no secrets)
├── icons/                      # 16/32/48/128 px (generated)
├── generate_icons.py           # dev-time icon generator (optional)
├── vendor/                     # Tesseract.js, jsQR, eng.traineddata
└── src/
    ├── background/service-worker.js   # context menu, side panel, tab ops
    ├── sidepanel/
    │   ├── sidepanel.html             # panel shell
    │   ├── sidepanel.css              # light professional theme
    │   └── sidepanel.js               # controller: scans, results, views
    ├── services/api.js                # the ONLY fetch() in the extension
    ├── components/ui.js               # DOM helpers, step loader, toggles
    ├── utils/
    │   ├── extractPageData.js         # injected page extractor (privacy-safe)
    │   └── riskFormatter.js           # risk → labels/classes (display only)
    └── vision/
        ├── ocr.js                     # local OCR + QR (side panel context)
        └── visual.js                  # local input-box detection
```

## Backend endpoints used

| Endpoint | Used for |
|---|---|
| `POST /api/analyze` | Page scans, URL scans, message/selection scans |
| `POST /api/vision/analyze` | Screenshot scans (Vision) |
| `GET /api/health` | Backend status in the panel header + Settings |

All contracts are documented in the repo root (`BUILD.md`, `app.py`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Header shows "Offline" | Start the server: `python3 app.py`. Check `config/config.js` points at the right port. |
| "VIGIL doesn't have permission to read this page" | Grant site access: VIGIL → ⚙ Settings → *Grant Access…*, or reload the page and rescan. |
| "VIGIL couldn't analyze this page" on chrome:// pages | Expected — browser pages can't be scanned. |
| Capture fails | Keep the browser window in the foreground while capturing; browser-internal pages can't be captured. |
| Changed the API URL but still offline | MV3 caches host permissions — add the host to `manifest.json` and reload the extension. |
