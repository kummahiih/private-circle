/**
 * Build the client-side loader HTML.
 */
export function buildLoader({ pageId, share1B64, ivB64, cipherB64, entries }) {
  const entriesJson = JSON.stringify(entries);
  const pageIdJson = JSON.stringify(pageId);
  const hasPrf = entries.some((e) => e.alg === 'WebAuthn-PRF');
  const hasPbkdf = entries.some((e) => e.alg === 'PBKDF2-SHA256' || !e.alg);
  return `<!DOCTYPE html>
<html lang="fi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow" />
  <title>Kirjaudu</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 3rem auto; padding: 0 1rem; }
    input, button { font-size: 16px; width: 100%; padding: 0.6rem; box-sizing: border-box; }
    button { margin-top: 0.75rem; cursor: pointer; }
    .hint { color: #555; font-size: 0.85rem; }
    .err { color: #b00020; }
    .sep { margin: 1.25rem 0 0.5rem; font-size: 0.8rem; color: #888; text-align: center; }
  </style>
</head>
<body>
  <h1>Kirjaudu</h1>
  <p class="hint">Sivu on salattu (<span id="pid"></span>).</p>
  ${hasPbkdf ? `<input id="pw" type="password" autocomplete="current-password" placeholder="Salasana" />
  <button type="button" id="go">Avaa salasanalla</button>` : ''}
  ${hasPrf ? `${hasPbkdf ? '<p class="sep">tai</p>' : ''}
  <button type="button" id="go-prf">Avaa passkeyllä (WebAuthn PRF)</button>` : ''}
  <p id="status" class="hint"></p>
  <script>
(function () {
  var PAGE_ID = ${pageIdJson};
  var SHARE1 = "${share1B64}";
  var IV = "${ivB64}";
  var CIPHER = "${cipherB64}";
  var ENTRIES = ${entriesJson};
  var ITER = 310000;
  document.getElementById("pid").textContent = PAGE_ID;

  function b64ToU8(b64) {
    var s = atob(b64);
    var u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  function xorU8(a, b) {
    var o = new Uint8Array(a.length);
    for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i];
    return o;
  }
  function buildPbkdf2Salt(randomSaltU8, pageId) {
    var pageBytes = new TextEncoder().encode(pageId);
    var out = new Uint8Array(randomSaltU8.length + pageBytes.length);
    out.set(randomSaltU8, 0);
    out.set(pageBytes, randomSaltU8.length);
    return out;
  }
  function prfSaltForPage(pageId) {
    return new TextEncoder().encode("circle-prf:v1:" + pageId);
  }

  async function deriveHash(password, saltU8, pageId) {
    var pbkdf2Salt = buildPbkdf2Salt(saltU8, pageId);
    var key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: pbkdf2Salt, iterations: ITER, hash: "SHA-256" },
      key,
      256
    );
    return new Uint8Array(bits);
  }

  async function tryDecryptWithHash(hashU8) {
    var share1 = b64ToU8(SHARE1);
    var iv = b64ToU8(IV);
    var cipher = b64ToU8(CIPHER);
    for (var i = 0; i < ENTRIES.length; i++) {
      var e = ENTRIES[i];
      var mask = b64ToU8(e.mask);
      if (hashU8.length !== mask.length) continue;
      var share2 = xorU8(hashU8, mask);
      var K = xorU8(share1, share2);
      try {
        var key = await crypto.subtle.importKey("raw", K, { name: "AES-GCM" }, false, ["decrypt"]);
        var plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipher);
        return new TextDecoder().decode(plain);
      } catch (err) { /* next */ }
    }
    return null;
  }

  async function tryUnlockPassword(password) {
    for (var i = 0; i < ENTRIES.length; i++) {
      var e = ENTRIES[i];
      if (e.alg && e.alg !== "PBKDF2-SHA256") continue;
      if (!e.salt) continue;
      var salt = b64ToU8(e.salt);
      var hash = await deriveHash(password, salt, PAGE_ID);
      var html = await tryDecryptWithHash(hash);
      if (html) return html;
    }
    return null;
  }

  async function tryUnlockPrf() {
    if (!window.PublicKeyCredential) throw new Error("Selain ei tue WebAuthn");
    var salt = prfSaltForPage(PAGE_ID);
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var cred = await navigator.credentials.get({
      publicKey: {
        challenge: challenge.buffer,
        rpId: location.hostname,
        userVerification: "preferred",
        timeout: 60000,
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    if (!cred) return null;
    var ext = cred.getClientExtensionResults();
    if (!ext || !ext.prf || !ext.prf.results || !ext.prf.results.first) {
      throw new Error("PRF-tulos puuttuu (authenticator ei tue tai ei palauttanut)");
    }
    var prfHash = new Uint8Array(ext.prf.results.first);
    return tryDecryptWithHash(prfHash);
  }

  function showHtml(html) {
    document.open();
    document.write(html);
    document.close();
  }

  var goBtn = document.getElementById("go");
  if (goBtn) {
    goBtn.addEventListener("click", function () {
      var status = document.getElementById("status");
      var pwEl = document.getElementById("pw");
      var pw = pwEl ? pwEl.value : "";
      status.className = "hint";
      status.textContent = "Avataan…";
      if (!pw) { status.textContent = "Syötä salasana."; status.className = "hint err"; return; }
      tryUnlockPassword(pw).then(function (html) {
        if (!html) {
          status.textContent = "Virheellinen salasana tai vioittunut data.";
          status.className = "hint err";
          return;
        }
        showHtml(html);
      }).catch(function () {
        status.textContent = "Purku epäonnistui.";
        status.className = "hint err";
      });
    });
  }

  var prfBtn = document.getElementById("go-prf");
  if (prfBtn) {
    prfBtn.addEventListener("click", function () {
      var status = document.getElementById("status");
      status.className = "hint";
      status.textContent = "Odota passkey-vahvistusta…";
      tryUnlockPrf().then(function (html) {
        if (!html) {
          status.textContent = "Passkey ei avannut sivua (väärä credential tai data).";
          status.className = "hint err";
          return;
        }
        showHtml(html);
      }).catch(function (e) {
        status.textContent = "PRF-virhe: " + (e && e.message ? e.message : e);
        status.className = "hint err";
      });
    });
  }
})();
  </script>
</body>
</html>
`;
}
