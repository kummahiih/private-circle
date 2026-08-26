/**
 * Build the client-side loader HTML (no inline scripts — strict CSP).
 * Secrets live in gate-config.json; logic in gate.js; styles in gate.css.
 */
export function buildLoaderHtml() {
  return `<!DOCTYPE html>
<html lang="fi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; frame-ancestors 'none'" />
  <title>Kirjaudu</title>
  <link rel="stylesheet" href="gate.css" />
</head>
<body>
  <h1>Kirjaudu</h1>
  <p class="hint">Sivu on salattu (<span id="pid"></span>).</p>
  <div id="pw-block" class="hidden">
    <input id="pw" type="password" autocomplete="current-password" placeholder="Salasana" />
    <button type="button" id="go">Avaa salasanalla</button>
  </div>
  <p id="sep" class="sep hidden">tai</p>
  <div id="prf-block" class="hidden">
    <button type="button" id="go-prf">Avaa passkeyllä (WebAuthn PRF)</button>
  </div>
  <p id="status" class="hint"></p>
  <script src="gate.js"></script>
</body>
</html>
`;
}

/**
 * Per-build secrets consumed by gate.js (not executable code).
 * Single-file: cipher + iv at top level (v1 compat).
 * Multifile: files map { relPath: { iv, cipher } }; top-level cipher is primary (usually index.html).
 */
export function buildGateConfig({ pageId, share1B64, ivB64, cipherB64, entries, files }) {
  const cfg = {
    v: files ? 2 : 1,
    pageId,
    share1: share1B64,
    iv: ivB64,
    cipher: cipherB64,
    entries,
  };
  if (files && Object.keys(files).length) {
    cfg.files = files;
  }
  return cfg;
}

/** @deprecated use buildLoaderHtml + buildGateConfig */
export function buildLoader(opts) {
  return buildLoaderHtml();
}
