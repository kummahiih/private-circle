/* enroll-core.js — shared helpers + password path */
(function (global) {
  var ITER = 310000;
  var lastPayload = null;
  var lastFilename = null;

  function $(id) { return document.getElementById(id); }

  function setStatus(msg, kind) {
    var el = $("status");
    el.textContent = msg || "";
    el.className = "status" + (kind ? " " + kind : "");
  }

  function b64(buf) {
    var bytes = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function normalizePageId(s) {
    return String(s || "").trim().toLowerCase().replace(/\s+/g, "-");
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

  function downloadText(filename, text) {
    var blob = new Blob([text], { type: "application/json;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function enableAfterMake(on) {
    $("btn-download").disabled = !on;
    $("btn-copy").disabled = !on;
  }

  function makeFilename(pageId, label, prefix) {
    return (prefix || "enroll-") + pageId + "-" + (label ? label.replace(/[^\w\-]+/g, "_") + "-" : "") + Date.now() + ".json";
  }

  function setPayload(obj, filename) {
    lastPayload = obj;
    lastFilename = filename;
    enableAfterMake(true);
  }

  function getPayload() { return lastPayload; }
  function getFilename() { return lastFilename; }

  // prefill pageId from query
  var params = new URLSearchParams(window.location.search);
  if (params.get("page") || params.get("pageId")) {
    $("pageId").value = params.get("page") || params.get("pageId");
  }
  if ($("cur-host")) $("cur-host").textContent = location.hostname || "(unknown)";

  $("btn-make").addEventListener("click", function () {
    lastPayload = null;
    enableAfterMake(false);
    var pageId = normalizePageId($("pageId").value);
    var pw = $("pw").value;
    var pw2 = $("pw2").value;
    var label = $("label").value.trim();

    if (!pageId || pageId.length < 2) {
      setStatus("Anna pageId (vähintään 2 merkkiä).", "err");
      return;
    }
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(pageId)) {
      setStatus("pageId: vain a-z, 0-9, piste, alaviiva, viiva.", "err");
      return;
    }
    if (!pw || pw.length < 8) {
      setStatus("Salasanassa vähintään 8 merkkiä.", "err");
      return;
    }
    if (pw !== pw2) {
      setStatus("Salasanat eivät täsmää.", "err");
      return;
    }
    if (!window.crypto || !crypto.subtle) {
      setStatus("Selain ei tue Web Crypto API:a.", "err");
      return;
    }

    setStatus("Lasketaan PBKDF2 (hetki)…");
    var randomSalt = crypto.getRandomValues(new Uint8Array(16));
    var pbkdf2Salt = buildPbkdf2Salt(randomSalt, pageId);

    crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"])
      .then(function (key) {
        return crypto.subtle.deriveBits(
          { name: "PBKDF2", salt: pbkdf2Salt, iterations: ITER, hash: "SHA-256" },
          key,
          256
        );
      })
      .then(function (bits) {
        var obj = {
          v: 1,
          pageId: pageId,
          alg: "PBKDF2-SHA256",
          iterations: ITER,
          hashBytes: 32,
          salt: b64(randomSalt),
          hash: b64(bits),
          created: new Date().toISOString()
        };
        if (label) obj.label = label;
        setPayload(obj, makeFilename(pageId, label));
        $("pw").value = "";
        $("pw2").value = "";
        setStatus("Valmis (PBKDF2). Lataa JSON tai kopioi. Salasana tyhjennetty.", "ok");
      })
      .catch(function (e) {
        setStatus("Virhe: " + (e && e.message ? e.message : e), "err");
      });
  });

  $("btn-download").addEventListener("click", function () {
    if (!lastPayload) return;
    downloadText(lastFilename, JSON.stringify(lastPayload, null, 2));
    setStatus("JSON ladattu: " + lastFilename, "ok");
  });

  $("btn-copy").addEventListener("click", function () {
    if (!lastPayload) return;
    var text = JSON.stringify(lastPayload, null, 2);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        setStatus("JSON kopioitu leikepöydälle.", "ok");
      }).catch(function () {
        setStatus("Leikepöytä epäonnistui — käytä latausta.", "err");
      });
    } else {
      setStatus("Leikepöytä ei saatavilla — käytä latausta.", "err");
    }
  });

  global.CircleEnroll = {
    $, setStatus, b64, normalizePageId, prfSaltForPage,
    setPayload, makeFilename, enableAfterMake, getPayload
  };
})(window);
