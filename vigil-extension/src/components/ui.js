/**
 * VIGIL Security — small shared UI helpers for the side panel.
 */
'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);

  /** Create an element with class, text, and children in one call. */
  function el(tag, { cls, text, children = [], attrs = {} } = {}) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    for (const child of children) if (child) node.append(child);
    return node;
  }

  /** Screen-reader announcements (polite) for async result changes. */
  const announcer = {
    say(message) {
      const region = $('#a11y-announcer');
      if (region) {
        region.textContent = '';
        setTimeout(() => { region.textContent = message; }, 30);
      }
    }
  };

  /**
   * Staged loading list. `steps` is [{key, label}]; statuses map to
   * ✓ (done), ◌ spinning (running), or idle ○.
   */
  function createStepList(container, steps) {
    container.replaceChildren();
    const items = new Map();
    for (const step of steps) {
      const li = el('li', { cls: 'step', attrs: { 'data-step': step.key } });
      const icon = el('span', { cls: 'step-icon', attrs: { 'aria-hidden': 'true' } });
      const label = el('span', { text: step.label });
      li.append(icon, label);
      container.append(li);
      items.set(step.key, { li, icon, labelNode: label, baseLabel: step.label });
    }
    return {
      set(key, status, detail) {
        const item = items.get(key);
        if (!item) return;
        item.li.classList.remove('done', 'running');
        item.li.setAttribute('aria-hidden', 'false');
        if (status === 'done') {
          item.li.classList.add('done');
          item.icon.textContent = '✓';
          item.labelNode.textContent = detail ? `${item.baseLabel} — ${detail}` : item.baseLabel;
        } else if (status === 'running') {
          item.li.classList.add('running');
          item.icon.textContent = '';
          item.labelNode.textContent = detail ? `${item.baseLabel} — ${detail}` : item.baseLabel;
        } else {
          item.icon.textContent = '○';
        }
      },
      reset() {
        for (const item of items.values()) {
          item.li.classList.remove('done', 'running');
          item.icon.textContent = '○';
          item.labelNode.textContent = item.baseLabel;
        }
      }
    };
  }

  /** ARIA switch toggle bound to a stored boolean. */
  function bindToggle(button, initial, onChange) {
    const render = () => button.setAttribute('aria-checked', String(initial.value));
    render();
    button.addEventListener('click', () => {
      initial.value = !initial.value;
      render();
      onChange(initial.value);
    });
    return { render };
  }

  self.VigilUI = { $, el, announcer, createStepList, bindToggle };
})();
