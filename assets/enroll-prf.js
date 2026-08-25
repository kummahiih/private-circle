/* enroll-prf.js — WebAuthn PRF path */
(function () {
  var CE = window.CircleEnroll;
  if (!CE) return;
  var $ = CE.$;

  $("btn-prf").addEventListener("click", async function () {
    CE.enableAfterMake(false);
    var pageId = CE.normalizePageId($("pageId").value);
    var label = $("label").value.trim();

    if (!pageId || pageId.length < 2) {
      CE.setStatus("Anna pageId (vähintään 2 merkkiä).", "err");
      return;
    }
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(pageId)) {
      CE.setStatus("pageId: vain a-z, 0-9, piste, alaviiva, viiva.", "err");
      return;
    }
    if (!window.PublicKeyCredential) {
      CE.setStatus("Selain ei tue WebAuthn / passkeytä.", "err");
      return;
    }

    CE.setStatus("Luodaan passkey ja pyydetään PRF… (vahvista laitteella)");

    try {
      var salt = CE.prfSaltForPage(pageId);
      var userId = crypto.getRandomValues(new Uint8Array(16));
      var challenge = crypto.getRandomValues(new Uint8Array(32));

      var createOpts = {
        publicKey: {
          rp: { id: location.hostname, name: "Circle enroll" },
          user: {
            id: userId,
            name: (label || "circle-user") + "@" + pageId,
            displayName: label || "Circle user"
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
          authenticatorSelection: {
            residentKey: "preferred",
            requireResidentKey: false,
            userVerification: "preferred"
          },
          timeout: 90000,
          challenge: challenge.buffer,
          extensions: { prf: { eval: { first: salt } } }
        }
      };

      var cred = await navigator.credentials.create(createOpts);
      if (!cred) throw new Error("Passkey-luonti peruutettiin");

      var prfFirst = null;
      var ext = cred.getClientExtensionResults();
      if (ext && ext.prf && ext.prf.results && ext.prf.results.first) {
        prfFirst = new Uint8Array(ext.prf.results.first);
      }

      if (!prfFirst) {
        CE.setStatus("PRF ei tullut createsta — pyydetään getillä…");
        var getChallenge = crypto.getRandomValues(new Uint8Array(32));
        var assertion = await navigator.credentials.get({
          publicKey: {
            challenge: getChallenge.buffer,
            rpId: location.hostname,
            allowCredentials: [{ type: "public-key", id: cred.rawId }],
            userVerification: "preferred",
            timeout: 60000,
            extensions: { prf: { eval: { first: salt } } }
          }
        });
        if (!assertion) throw new Error("PRF-get peruutettiin");
        var aext = assertion.getClientExtensionResults();
        if (!aext || !aext.prf || !aext.prf.results || !aext.prf.results.first) {
          throw new Error("Authenticator ei palauttanut PRF-tulosta. Tarvitaan PRF-tuki (Chrome 116+, Safari 18+, Firefox 135+ + yhteensopiva authenticator).");
        }
        prfFirst = new Uint8Array(aext.prf.results.first);
      }

      if (prfFirst.length !== 32) {
        throw new Error("Odottamaton PRF-pituus: " + prfFirst.length);
      }

      var obj = {
        v: 1,
        pageId: pageId,
        alg: "WebAuthn-PRF",
        hashBytes: 32,
        hash: CE.b64(prfFirst),
        created: new Date().toISOString(),
        rpId: location.hostname
      };
      if (label) obj.label = label;

      CE.setPayload(obj, CE.makeFilename(pageId, label, "enroll-prf-"));
      CE.setStatus("Valmis (WebAuthn-PRF). Lataa JSON. Passkey on nyt tällä originilla.", "ok");
    } catch (e) {
      CE.setStatus("PRF-virhe: " + (e && e.message ? e.message : e), "err");
    }
  });
})();
