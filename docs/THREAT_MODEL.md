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

### Information disclosure
- **Offline PBKDF2 attack:** Attacker downloads config + tries passwords against masks. *Severity:* High for weak passwords.
- **Hash + mask leak:** If enroll JSON and dist both leak, recovery of `K` is direct. *Severity:* Critical for operational mistakes.
- **Decrypted HTML XSS:** Content is operator-controlled; malicious content runs with page origin privileges after unlock.

### Denial of service
- Destroyed or incomplete dist; lost sole PRF credential without password backup → permanent lockout.

### Elevation of privilege
- Not a multi-tenant server; “privilege” is ability to read clear content. Equivalent to learning a password or possessing the authenticator.

## Prioritized Mitigation Plan

### Critical
- [x] **Never publish `hashes/` or enroll JSON** alongside dist. Documented; `encryptPage` post-check + CI `npm pack` guard.
- [ ] **Treat weak-password circles as public-readable** under offline attack; enforce strong passwords or PRF-only.
- [ ] **PRF enroll only on production origin** (same RP ID as gate).

### High
- [ ] Keep **password backup enrollment** if PRF is primary (recovery path).
- [ ] **Rotate build (`K`)** and re-enroll when any hash set may have leaked.
- [ ] Ensure deployed **HTTP CSP** matches loader meta (no `'unsafe-inline'`).
- [x] Remove or stop shipping **duplicate enroll sources** in package `assets/` once circle-enroll is sole source (reduce drift).

### Medium
- [x] Rate-limit is impossible client-side; document offline threat in user-facing security notes (already partially in `assets/security.md`).
- [ ] Consider **SRI** for gate.js when operators mirror assets.
- [x] CI check: fail if dist contains plaintext markers from content / `hashes/` folder.

### Low
- [ ] Expand tests for enroll.css copy path and CSP meta snapshots.
- [ ] Document browser matrix for WebAuthn PRF.
