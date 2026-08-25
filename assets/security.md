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

## Build hygiene

- Run encrypt script on a trusted machine
- Delete or vault `hashes/` after deploy if policy requires
- Rotate all passwords / re-enroll when `K` is rotated (rebuild)

## Loader

- Generic failure messages
- Prefer not to `eval` string code; decrypt to HTML string and assign to `document.documentElement.innerHTML` only for operator-controlled content, or write to `iframe.srcdoc`
- HTTPS only (Vercel default)
