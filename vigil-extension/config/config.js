/**
 * VIGIL Security — extension configuration.
 *
 * There are NO API SECRETS in this file. VIGIL's backend (app.py / the
 * serverless api/ functions) is the analysis engine; the extension is only a
 * client of it and never talks to Gemini or any other LLM directly.
 *
 * Set API_BASE_URL here. In development this points at the local VIGIL
 * server. To use a different backend (a deployed instance, a different port,
 * an HTTPS host), change API_BASE_URL below AND add a matching entry to
 * manifest.json -> host_permissions (MV3 requires hosts to be declared
 * statically, or requested at runtime from the Settings screen), then reload
 * the extension at chrome://extensions.
 */
'use strict';

const VIGIL_CONFIG = Object.freeze({
  /** Base URL of the VIGIL analysis backend. No trailing slash. */
  API_BASE_URL: 'http://127.0.0.1:8000',

  /**
   * How long a single API call may take before the extension gives up and
   * offers "Try Again". Local VIGIL typically answers in well under a second.
   */
  REQUEST_TIMEOUT_MS: 30000,

  /** The local VIGIL rules engine caps content at 200,000 characters. */
  MAX_PAGE_TEXT_CHARS: 200000,

  /** Screened-out schemes that extensions cannot analyze. */
  RESTRICTED_URL_SCHEMES: [
    'chrome:', 'edge:', 'about:', 'view-source:', 'devtools:',
    'chrome-extension:', 'https://chromewebstore.google.com'
  ],

  /** History is metadata-only and capped so storage stays tiny. */
  HISTORY_LIMIT: 40
});

if (typeof self !== 'undefined') {
  self.VIGIL_CONFIG = VIGIL_CONFIG;
}
