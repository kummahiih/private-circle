/**
 * gate.js — external unlock logic for private-circle (strict CSP friendly).
 * Loads per-build secrets from ./gate-config.json (same origin).
 * Single-file (v1): decrypt cipher → document.write HTML.
 * Multifile (v2): decrypt files map → blob URLs for js/css → rewrite HTML → write.
 * No eval / new Function / inline script injection.
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

  /** Derive AES key K from hash via share1/share2 masks. Returns CryptoKey or null. */
  async function tryKeyFromHash(cfg, hashU8) {
    var share1 = b64ToU8(cfg.share1);
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
        // Probe primary cipher so we know this K works
        var iv = b64ToU8(cfg.iv);
        var cipher = b64ToU8(cfg.cipher);
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipher);
        return key;
      } catch (err) {
        /* try next entry */
      }
    }
    return null;
  }

  async function decryptWithKey(key, ivB64, cipherB64) {
    var iv = b64ToU8(ivB64);
    var cipher = b64ToU8(cipherB64);
    var plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      cipher
    );
    return new TextDecoder().decode(plain);
  }

  async function tryDecryptWithHash(cfg, hashU8) {
    var key = await tryKeyFromHash(cfg, hashU8);
    if (!key) return null;
    try {
      return await decryptWithKey(key, cfg.iv, cfg.cipher);
    } catch (e) {
      return null;
    }
  }

  async function decryptAllFiles(cfg, key) {
    var files = cfg.files || {};
    var out = {};
    var keys = Object.keys(files);
    for (var i = 0; i < keys.length; i++) {
      var rel = keys[i];
      var meta = files[rel];
      out[rel] = await decryptWithKey(key, meta.iv, meta.cipher);
    }
    return out;
  }

  function mimeFor(rel) {
    if (rel.endsWith(".css")) return "text/css";
    if (rel.endsWith(".js")) return "text/javascript";
    if (rel.endsWith(".html") || rel.endsWith(".htm")) return "text/html";
    return "text/plain";
  }

  function rewriteHtmlToBlobs(html, blobsByRel) {
    var byName = {};
    var rels = Object.keys(blobsByRel);
    for (var i = 0; i < rels.length; i++) {
      var rel = rels[i];
      var url = blobsByRel[rel];
      byName[rel] = url;
      var base = rel.split("/").pop();
      if (base) byName[base] = url;
    }

    function replaceAttr(tag, attr, htmlIn) {
      var re = new RegExp(
        "(<" + tag + "\\b[^>]*\\b" + attr + "\\s*=\\s*)([\"'])([^\"']+)\\2",
        "gi"
      );
      return htmlIn.replace(re, function (m, pre, q, path) {
        if (/^(https?:|data:|blob:|\/\/)/i.test(path)) return m;
        var clean = path.replace(/^\.\//, "");
        var url = byName[clean] || byName[path];
        if (!url) return m;
        return pre + q + url + q;
      });
    }

    var out = html;
    out = replaceAttr("script", "src", out);
    out = replaceAttr("link", "href", out);
    return out;
  }

  async function unlockWithKey(cfg, key) {
    if (cfg.files && Object.keys(cfg.files).length > 0) {
      var plainMap = await decryptAllFiles(cfg, key);
      var blobs = {};
      var rels = Object.keys(plainMap);
      for (var i = 0; i < rels.length; i++) {
        var rel = rels[i];
        var text = plainMap[rel];
        var blob = new Blob([text], { type: mimeFor(rel) });
        blobs[rel] = URL.createObjectURL(blob);
      }
      var html =
        plainMap["index.html"] ||
        plainMap["index-plaintext.html"] ||
        null;
      if (!html) {
        for (var j = 0; j < rels.length; j++) {
          if (/\.html?$/i.test(rels[j])) {
            html = plainMap[rels[j]];
            break;
          }
        }
      }
      if (!html) {
        html = await decryptWithKey(key, cfg.iv, cfg.cipher);
      }
      html = rewriteHtmlToBlobs(html, blobs);
      if (!/Content-Security-Policy/i.test(html)) {
        html = html.replace(
          /<head([^>]*)>/i,
          '<head$1><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'; script-src \'self\' blob:; style-src \'self\' blob:; connect-src \'self\'; img-src \'self\' data:; font-src \'self\' data:; object-src \'none\'; frame-ancestors \'none\'" />'
        );
      }
      showHtml(html);
      return;
    }
    var single = await decryptWithKey(key, cfg.iv, cfg.cipher);
    showHtml(single);
  }

  async function tryUnlockPassword(cfg, password) {
    var entries = cfg.entries || [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.alg && e.alg !== "PBKDF2-SHA256") continue;
      if (!e.salt) continue;
      var salt = b64ToU8(e.salt);
      var hash = await deriveHash(password, salt, cfg.pageId);
      var key = await tryKeyFromHash(cfg, hash);
      if (key) {
        await unlockWithKey(cfg, key);
        return true;
      }
    }
    return false;
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
    if (!cred) return false;
    var ext = cred.getClientExtensionResults();
    if (!ext || !ext.prf || !ext.prf.results || !ext.prf.results.first) {
      throw new Error(
        "PRF-tulos puuttuu (authenticator ei tue tai ei palauttanut)"
      );
    }
    var prfHash = new Uint8Array(ext.prf.results.first);
    var key = await tryKeyFromHash(cfg, prfHash);
    if (!key) return false;
    await unlockWithKey(cfg, key);
    return true;
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
          .then(function (ok) {
            if (!ok) {
              setStatus("Virheellinen salasana tai vioittunut data.", true);
            }
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
          .then(function (ok) {
            if (!ok) {
              setStatus(
                "Passkey ei avannut sivua (väärä credential tai data).",
                true
              );
            }
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
