# Threat Model — @kummahiih/private-circle

## Trust Boundaries

| Boundary | Trusted | Untrusted |
|----------|---------|-----------|
| Operator build machine | Cleartext, hashes, `K` generation | — |
| Public CDN / static host | — | All dist files (ciphertext, masks, share1, JS) |
| Visitor browser | After successful unlock, decrypted DOM | Before unlock; extensions; XSS in decrypted HTML |
| Enroll origin | Same origin as gate for PRF | Cross-origin enroll hosts |
| npm supply chain | Pinned/semver deps | Compromised publish tokens / packages |

## Identified Threats

### Spoofing
- Phishing enroll or gate pages on lookalike domains.
- WebAuthn RP ID mismatch: PRF enroll on wrong origin never unlocks production gate.

### Tampering
- Modified `gate.js` on compromised host → exfiltrate password or key material (CSP `connect-src 'self'` limits destinations to same origin only).
- Tampered `gate-config.json` → denial of decrypt or malicious ciphertext (still need valid K path).
- Corrupted AES-GCM authentication tags on config/ciphertext entries are currently swallowed while probing derived keys; low exploitability today (operator-controlled entries, no extra `connect-src`) but can mask tampering.

### Information disclosure
- **Offline PBKDF2 attack:** Attacker downloads config + tries passwords against masks. *Severity:* High for weak passwords.
- **Hash + mask leak:** If enroll JSON and dist both leak, recovery of `K` is direct. *Severity:* Critical for operational mistakes.
- **Decrypted HTML XSS:** Content is operator-controlled; malicious content runs with page origin privileges after unlock.
- **AES-GCM IV reuse under shared `K`:** Multifile builds use one content key `K` with a fresh 12-byte IV per file, but IVs are not checked for uniqueness. Repeated IV + same key is catastrophic (plaintext recovery). *Severity:* Critical if a collision occurs.
- **Weak PBKDF2 parameters:** Loader currently *warns* if enroll JSON has iterations < 310000 instead of rejecting. A weak enroll can be built into a published circle. *Severity:* High/Critical for operational mistakes.

### Denial of service
- Destroyed or incomplete dist; lost sole PRF credential without password backup → permanent lockout.

### Elevation of privilege
- Not a multi-tenant server; “privilege” is ability to read clear content. Equivalent to learning a password or possessing the authenticator.

### Deployment / host misconfiguration
- Missing or wrong `Content-Type` on static assets (e.g. `gate.js` as `text/plain`) can interact badly with CSP and script execution. Threat model assumes the host sets types and CSP correctly.

## Prioritized Mitigation Plan

### Critical
- [x] **Never publish `hashes/` or enroll JSON** alongside dist. Documented; `encryptPage` post-check + CI `npm pack` guard.
- [x] **PRF enroll only on production origin** (same RP ID as gate). Documented in README operator runbook + circle-enroll.
- [ ] **Treat weak-password circles as public-readable** under offline attack; enforce strong passwords or PRF-only.
- [ ] **Reject AES-GCM IV collisions** when encrypting multiple files under the same `K` (`src/encrypt-page.mjs`). Track used IVs and fail the build on reuse; do not rely on 12-byte randomness alone.
- [ ] **Fail closed on weak PBKDF2 iterations** in `src/load-hashes.mjs`: throw if `PBKDF2-SHA256` iterations < 310000 instead of `console.warn`.
- [ ] **Distinguish AES-GCM auth-tag failures** in `assets/gate.js` key-probe `catch` (defense in depth). Still try the next entry, but do not treat every decrypt error as a silent miss; optionally log suspicious authentication failures.

### High
- [x] Keep **password backup enrollment** if PRF is primary (recovery path). Documented in README operator runbook + security.md.
- [x] **Rotate build (`K`)** and re-enroll when any hash set may have leaked. Documented in README operator runbook.
- [x] Ensure deployed **HTTP CSP** matches loader meta (no `'unsafe-inline'`).
- [x] Remove or stop shipping **duplicate enroll sources** in package `assets/` once circle-enroll is sole source (reduce drift).

### Medium
- [x] Rate-limit is impossible client-side; document offline threat in user-facing security notes (already in `assets/security.md`).
- [x] Optional **SRI** for gate.js — **deferred**. Same-origin + strict CSP cover the primary threat; revisit if operators commonly mirror assets to third-party hosts.
- [x] CI check: fail if dist contains plaintext markers from content / `hashes/` folder.
- [ ] **Document required HTTP `Content-Type` headers** in the operator runbook (`gate.js` → `application/javascript`, `gate.css` → `text/css`, `gate-config.json` → `application/json`, `index.html` → `text/html; charset=utf-8`, plus CSP on all responses).

### Low
- [x] Expand tests for enroll.css copy path and CSP meta snapshots.
- [x] Document browser matrix for WebAuthn PRF.
