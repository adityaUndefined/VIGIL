# VIGIL Agent Guard — Chromium extension

Asks the local VIGIL guard (`POST /guard`) before an agent-proposed action or
any form submit happens on a page. On `DENY` it cancels the action and shows a
block card in a closed shadow root that page CSS cannot touch.

## Install

1. Start the guard server (repo root):
   ```bash
   python3 guard_server.py          # http://127.0.0.1:8000
   ```
2. `chrome://extensions` → enable **Developer mode**.
3. **Load unpacked** → select this `guard-extension/` folder.
4. Reload the extension at `chrome://extensions` after every change to
   `background.js`, `guard-content.js`, or `manifest.json`.

## How it talks to the guard

- `guard-content.js` walks `document.body` (text nodes + comments), keeps only
  what fails `checkVisibility` (or is < 2px font / pushed off-screen), and sends
  it as `source.hidden_text` with the proposed action to
  `background.js` via `chrome.runtime.sendMessage`.
- `background.js` makes the actual `fetch` (service-worker fetch is not subject
  to the page's CORS/mixed-content rules; a content script's would be) and
  returns the verdict. If the guard is unreachable it answers
  `WARN / guard_unreachable` so the page can degrade sensibly.
- On `DENY` for a form submit the submit event stays cancelled; otherwise the
  form is marked and re-submitted with `form.requestSubmit()`.

## Manifest notes (learned the hard way)

- `host_permissions` must cover **the pages you want guarded**, not just the
  guard server. In Manifest V3 a `content_scripts` match is silently skipped
  unless some `host_permissions` entry covers that page's origin — this is why
  the manifest grants `http://*/*` + `https://*/*`. Chrome will show a
  "read and change data on all websites" prompt on install.
- `background.js`'s fetch needs `http://127.0.0.1:8000/*` in
  `host_permissions` (service-worker fetch bypasses page CORS only for
  hosts declared there).
- A content script runs in an isolated world: page scripts and content-script
  `window` properties are invisible to each other (the DOM is shared). The
  extension therefore signals readiness via
  `document.documentElement.dataset.vigilContent = "1"` — that is how the E2E
  driver (and you, in DevTools) can tell the content script is active.

## Demo

Open `demo/hijack_demo.html` over `http://` (e.g. `python3 -m http.server 9000`
in the repo root, then `http://127.0.0.1:9000/demo/hijack_demo.html`). Content
scripts do not run on `file://` pages by default.

- Extension off / guard server down → the naive agent "forwards" (`Forwarded (!)`).
- Extension on + guard running → block card appears and the page shows `BLOCKED by VIGIL`.
- The form on the hijack page is never processed: DENY cancels the submit.
- `demo/clean_form.html` is the control: its ordinary form submits normally
  (ALLOW path — the guard does not get in the way of benign pages).

## End-to-end test

With Node available:

```bash
npm i puppeteer                # or set PUPPETEER_MODULE to an existing install
npm run guard:e2e              # boots server + demo, drives headless Chrome, 9 checks
```

The E2E verifies: service worker load, hijack flow blocked with block card,
`/explain` wording swap, hijacked form submit cancelled, clean form allowed,
and guard-unreachable degradation.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Block card never appears | In the page console, `document.documentElement.dataset.vigilContent` should be `"1"`. If undefined: page must be `http(s)://` (not `file://`), the page origin must be covered by `host_permissions`, and the extension must be reloaded after manifest changes. |
| `sendMessage` returns undefined | The service worker listener is missing `return true`, or `host_permissions` lacks `http://127.0.0.1:8000/*`. |
| Guard answers `WARN / guard_unreachable` | `python3 guard_server.py` is not running on `:8000`. |
