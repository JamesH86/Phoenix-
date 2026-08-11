(function attachPhoenixRedaction(root) {
  "use strict";

  function redactSensitiveNumbers(value) {
    return String(value ?? "")
      .replace(/\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g, "[redacted identifier]")
      .replace(/\b(?:\d[ -]*?){13,19}\b/g, "[redacted payment number]")
      .replace(/(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}\b/g, "[redacted phone number]")
      .replace(/\b(account|routing|member|customer|employee)[ _-]?(number|id)\s*[:=]\s*[a-z0-9-]+/gi, "$1 $2: [redacted]");
  }

  const api = Object.freeze({ redactSensitiveNumbers });
  root.PhoenixRedaction = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
