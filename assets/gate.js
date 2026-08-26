/**
 * gate.js — external unlock logic for private-circle (strict CSP friendly).
 * Loads per-build secrets from ./gate-config.json (same origin).
 */
(function () {
  var ITER = 310000;

  function $(id) {
    return document.getElementById(id);
  }

  function setStatus(msg, isErr) {
    var el = $("status");
    if (!el) return;
    el.textContent = msg || "";
    el.className = isErr ? "hint err" : "hint";
  }

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
    var key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: pbkdf2Salt, iterations: ITER, hash: "SHA-256" },
      key,
      256
    );
    return new Uint8Array(bits);
  }

  async function tryDecryptWithHash(cfg, hashU8) {
    var share1 = b64ToU8(cfg.share1);
    var iv = b64ToU8(cfg.iv);
    var cipher = b64ToU8(cfg.cipher);
    var entries = cfg.entries || [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var mask = b64ToU8(e.mask);
      if (hashU8.length !== mask.length) continue;
      var share2 = xorU8(hashU8, mask);
      var K = xorU8(share1, share2);
      try {
        var key = await crypto.subtle.importKey(
          "raw",
          K,
          { name: "AES-GCM" },
          false,
          ["decrypt"]
        );
        var plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          key,
          cipher
        );
        return new TextDecoder().decode(plain);
      } catch (err) {
        /* try next entry */
      }
    }
    return null;
  }

  async function tryUnlockPassword(cfg, password) {
    var entries = cfg.entries || [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.alg && e.alg !== "PBKDF2-SHA256") continue;
      if (!e.salt) continue;
      var salt = b64ToU8(e.salt);
      var hash = await deriveHash(password, salt, cfg.pageId);
      var html = await tryDecryptWithHash(cfg, hash);
      if (html) return html;
    }
    return null;
  }

  async function tryUnlockPrf(cfg) {
    if (!window.PublicKeyCredential) {
      throw new Error("Selain ei tue WebAuthn");
    }
    var salt = prfSaltForPage(cfg.pageId);
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var cred = await navigator.credentials.get({
      publicKey: {
        challenge: challenge.buffer,
        rpId: location.hostname,
        userVerification: "preferred",
        timeout: 60000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    if (!cred) return null;
    var ext = cred.getClientExtensionResults();
    if (!ext || !ext.prf || !ext.prf.results || !ext.prf.results.first) {
      throw new Error(
        "PRF-tulos puuttuu (authenticator ei tue tai ei palauttanut)"
      );
    }
    var prfHash = new Uint8Array(ext.prf.results.first);
    return tryDecryptWithHash(cfg, prfHash);
  }

  function showHtml(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function wireUi(cfg) {
    var entries = cfg.entries || [];
    var hasPbkdf = entries.some(function (e) {
      return e.alg === "PBKDF2-SHA256" || !e.alg;
    });
    var hasPrf = entries.some(function (e) {
      return e.alg === "WebAuthn-PRF";
    });

    var pid = $("pid");
    if (pid) pid.textContent = cfg.pageId || "";

    var pwBlock = $("pw-block");
    var prfBlock = $("prf-block");
    var sep = $("sep");
    if (pwBlock) pwBlock.classList.toggle("hidden", !hasPbkdf);
    if (prfBlock) prfBlock.classList.toggle("hidden", !hasPrf);
    if (sep) sep.classList.toggle("hidden", !(hasPbkdf && hasPrf));

    var goBtn = $("go");
    if (goBtn && hasPbkdf) {
      goBtn.addEventListener("click", function () {
        var pwEl = $("pw");
        var pw = pwEl ? pwEl.value : "";
        setStatus("Avataan…", false);
        if (!pw) {
          setStatus("Syötä salasana.", true);
          return;
        }
        tryUnlockPassword(cfg, pw)
          .then(function (html) {
            if (!html) {
              setStatus("Virheellinen salasana tai vioittunut data.", true);
              return;
            }
            showHtml(html);
          })
          .catch(function () {
            setStatus("Purku epäonnistui.", true);
          });
      });
    }

    var prfBtn = $("go-prf");
    if (prfBtn && hasPrf) {
      prfBtn.addEventListener("click", function () {
        setStatus("Odota passkey-vahvistusta…", false);
        tryUnlockPrf(cfg)
          .then(function (html) {
            if (!html) {
              setStatus(
                "Passkey ei avannut sivua (väärä credential tai data).",
                true
              );
              return;
            }
            showHtml(html);
          })
          .catch(function (e) {
            setStatus(
              "PRF-virhe: " + (e && e.message ? e.message : e),
              true
            );
          });
      });
    }
  }

  function boot() {
    fetch("gate-config.json", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("gate-config.json puuttuu (" + r.status + ")");
        return r.json();
      })
      .then(function (cfg) {
        if (!cfg || !cfg.pageId || !cfg.share1 || !cfg.iv || !cfg.cipher) {
          throw new Error("gate-config.json on vaillinainen");
        }
        wireUi(cfg);
      })
      .catch(function (e) {
        setStatus(
          "Lataus epäonnistui: " + (e && e.message ? e.message : e),
          true
        );
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
