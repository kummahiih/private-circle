# Enrollment JSON format

Produced by `enroll.html`. Sent privately to the site operator. **Not** deployed.

## Password (PBKDF2)

```json
{
  "v": 1,
  "pageId": "metsa-piiri",
  "alg": "PBKDF2-SHA256",
  "iterations": 310000,
  "hashBytes": 32,
  "salt": "<base64 16 random bytes>",
  "hash": "<base64 32 bytes>",
  "created": "<ISO-8601>",
  "label": "<optional string>"
}
```

`iterations` must be **at least 310000**. Encrypt rejects weaker enroll files.

### pageId binding (PBKDF2)

```text
pbkdf2Salt = randomSalt_bytes || UTF-8(pageId)
hash = PBKDF2-SHA256(password, pbkdf2Salt, 310000, 32 bytes)
```

- `salt` field stores only the 16 random bytes
- `pageId` must match encrypt `--page-id` and the loader
- Same password + different `pageId` → different hash

## Passkey / WebAuthn PRF

```json
{
  "v": 1,
  "pageId": "metsa-piiri",
  "alg": "WebAuthn-PRF",
  "hashBytes": 32,
  "hash": "<base64 32-byte PRF output>",
  "created": "<ISO-8601>",
  "label": "<optional string>",
  "rpId": "<hostname at enrollment>"
}
```

### PRF binding

```text
prfSalt = UTF-8("circle-prf:v1:" + pageId)
hash = authenticator.PRF(credential, prfSalt)   // 32 bytes
```

- The passkey (credential) is bound to the **origin / RP ID** where enrollment was performed.
- For the gated page to unlock with the same passkey, enrollment **must** happen on the same origin (or a related origin that the browser allows).
- `circle-enroll.vercel.app` and `hello-circle-demo.vercel.app` are different origins → PRF enroll on the public enroll tool will **not** work for a different gated site unless you host enroll on the gated site’s domain.
- Same passkey + different `pageId` → different PRF output (because salt includes pageId).

## Enroll URL

```text
enroll.html?page=metsa-piiri
```

pre-fills the pageId field.

## Production ops (summary)

- **PRF:** enroll and gate must share the same origin (RP ID). Prefer PRF for high-value circles; keep a password backup if recovery is required.
- **Hashes:** never commit real enroll JSON to public git; never ship with `dist/`. Rotate build key `K` and re-enroll if hashes may have leaked with masks.
- **Headers:** host must serve correct `Content-Type` and CSP (see README operator runbook).

See package README operator runbook and `docs/THREAT_MODEL.md`.
