# Security notes — private circle page

## What is protected

- Page body at rest on the CDN (AES-GCM ciphertext)
- Passwords never need to sit in git if enrollment JSON is used

## What is not protected

- Offline password guessing against downloaded ciphertext + masks (PBKDF2 entries)
- For WebAuthn-PRF entries the offline attack surface is much smaller: the attacker needs the authenticator (or a broken platform) to evaluate the PRF
- XSS in the **decrypted** HTML (treat content as trusted operator HTML only)
- Operator laptop if enroll JSON files are stolen before build
- Anyone who obtains both enroll `hash` and published `mask`
- Passkey loss / no recovery: if the only unlock is PRF and the authenticator is lost, content is unrecoverable (keep a password backup or recovery path)

## Operator runbook (production)

1. **Same-origin enroll for PRF** — Host enroll on the gated page’s origin (RP ID match). Cross-origin public enroll is PBKDF2-only.
2. **Prefer WebAuthn-PRF** for high-value circles; keep a password backup enrollment if recovery is required.
3. **Never commit real `hashes/`** to public git; **never publish `hashes/` with `dist/`**.
4. **Rotate `K` + re-enroll** when any hash set may have leaked with published masks.

## Hashes hygiene (critical)

- **Never commit real `hashes/`** (enroll JSON with live user hashes) to a public repo. Demo hashes are the only exception and must be labeled as such.
- **Never publish `hashes/` with `dist/`**. Encrypt reads hashes at build time only; the output directory must not contain a `hashes/` folder or enroll JSON files.
- If both enroll `hash` and published `mask` leak, recovery of `K` is direct — treat as critical operational failure and rotate.
- Delete or vault `hashes/` after deploy if policy requires.
- Rotate all passwords / re-enroll when `K` is rotated (rebuild).

## Build hygiene

- Run encrypt script on a trusted machine
- `encryptPage` post-check fails if `dist/hashes` exists or obvious plaintext markers appear in text files under dist
- Package `files` field and CI `npm pack` check exclude `hashes/`

## Loader

- Generic failure messages
- Prefer not to `eval` string code; decrypt to HTML string and assign to `document.documentElement.innerHTML` only for operator-controlled content, or write to `iframe.srcdoc`
- HTTPS only (Vercel default)
