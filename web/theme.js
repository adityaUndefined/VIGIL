/**
 * VIGIL — shared theme controller (all pages).
 *
 * Order of truth: saved choice in localStorage ("dark"/"light") wins;
 * otherwise the OS prefers-color-scheme is followed. The pre-paint block
 * below runs inline (before the stylesheet finishes applying) so a dark-mode
 * visitor never sees a white flash; the toggle part activates once the
 * #theme-toggle button exists.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'vigil-theme';

  function savedTheme() {
    try { return localStorage.getItem(STORAGE_KEY); } catch { return null; }
  }

  function systemDark() {
    return typeof window.matchMedia === 'function'
      && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function isDark() {
    var saved = savedTheme();
    return saved ? saved === 'dark' : systemDark();
  }

  function render(root) {
    var dark = isDark();
    root.dataset.theme = dark ? 'dark' : 'light';
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = dark ? '#171512' : '#f3f5f1';
  }

  // 1) Pre-paint: runs immediately, before the body exists.
  render(document.documentElement);

  // 2) Follow OS changes only while the user has not chosen explicitly.
  if (typeof window.matchMedia === 'function') {
    var query = window.matchMedia('(prefers-color-scheme: dark)');
    var onSchemeChange = function (event) {
      if (!savedTheme()) render(document.documentElement);
    };
    if (typeof query.addEventListener === 'function') query.addEventListener('change', onSchemeChange);
    else if (typeof query.addListener === 'function') query.addListener(onSchemeChange);
  }

  // 3) Toggle: activates when the DOM is ready (script is loaded with defer
  //    or at the end of body on every page).
  function activate() {
    var toggle = document.querySelector('#theme-toggle');
    if (!toggle || toggle.dataset.themeBound === 'true') return;
    toggle.dataset.themeBound = 'true';

    var sync = function () {
      var dark = isDark();
      toggle.textContent = dark ? '☀️' : '🌙';
      toggle.setAttribute('aria-pressed', String(dark));
      toggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
      toggle.title = dark ? 'Switch to light theme' : 'Switch to dark theme';
    };
    sync();

    toggle.addEventListener('click', function () {
      var next = isDark() ? 'light' : 'dark';
      try { localStorage.setItem(STORAGE_KEY, next); } catch { /* keep working in-session */ }
      render(document.documentElement);
      sync();
      // Let page scripts (app.js) react if they care.
      document.dispatchEvent(new CustomEvent('vigil-theme-changed'));
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', activate);
  } else {
    activate();
  }
})();
