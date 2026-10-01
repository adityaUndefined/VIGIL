/**
 * VIGIL Security — risk display formatting.
 *
 * The backend is the only source of truth for risk. This file only maps the
 * backend's values to display strings/classes — it never invents a risk
 * level, never computes a score, and never overrides a decision.
 */
'use strict';

(() => {
  // ARIA text uses words + position, never color alone.
  const RISK = {
    low: {
      label: 'Safe',
      headline: 'No significant threats detected.',
      summary: 'No known phishing or scam signals were found. This is not a guarantee — stay alert for anything unusual.',
      cls: 'risk-safe',
      icon: '✓',
      aria: 'Result: Safe. No known risk signals.'
    },
    medium: {
      label: 'Warning',
      headline: 'Warning signs detected. Pause and verify.',
      summary: 'VIGIL found signals often used in scams. Verify through a trusted channel before acting.',
      cls: 'risk-warn',
      icon: '!',
      aria: 'Result: Warning. Suspicious signals detected; verify before acting.'
    },
    high: {
      label: 'High Risk',
      headline: 'High risk. Do not proceed.',
      summary: 'This content shows strong signs of a scam or phishing attempt. Do not enter information or make payments.',
      cls: 'risk-high',
      icon: '!',
      aria: 'Result: High risk. Do not proceed; strong scam signals detected.'
    }
  };

  const DECISION_TEXT = { ALLOW: 'Safe', WARN: 'Warning', DENY: 'High Risk' };

  /** Backend "low|medium|high" → display bundle. Unknown values degrade safely. */
  function fromRiskLevel(level) {
    return RISK[String(level || '').toLowerCase()] || RISK.low;
  }

  /** Backend "ALLOW|WARN|DENY" → display bundle. */
  function fromDecision(decision) {
    const level = { ALLOW: 'low', WARN: 'medium', DENY: 'high' }[decision] || 'low';
    return RISK[level];
  }

  /** CSS class for severity chips (evidence severity / indicator severity). */
  function severityClass(severity) {
    switch (String(severity || '').toLowerCase()) {
      case 'high': return 'sev-high';
      case 'medium': return 'sev-medium';
      default: return 'sev-info';
    }
  }

  function severityIcon(severity) {
    switch (String(severity || '').toLowerCase()) {
      case 'high': return '!';
      case 'medium': return '!';
      default: return '✓';
    }
  }

  function severityText(severity) {
    switch (String(severity || '').toLowerCase()) {
      case 'high': return 'High severity';
      case 'medium': return 'Medium severity';
      default: return 'Informational';
    }
  }

  /** Time string for history rows, e.g. "14:32". */
  function timeString(ts) {
    try {
      return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  }

  /** "url_insecure_transport" → "URL Insecure Transport" (display only). */
  function prettifyLabel(value) {
    const text = String(value || '').replace(/[_-]+/g, ' ').trim();
    if (!text) return 'Indicator';
    const upper = { url: 'URL', otp: 'OTP', llm: 'LLM', http: 'HTTP', https: 'HTTPS', api: 'API' };
    return text
      .split(' ')
      .map((word) => upper[word.toLowerCase()] || word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  self.VigilRisk = {
    fromRiskLevel,
    fromDecision,
    DECISION_TEXT,
    severityClass,
    severityIcon,
    severityText,
    timeString,
    prettifyLabel
  };
})();
