# Architecture Detail — @kummahiih/private-circle

## Network Topology

- **Build:** local/CI only; no required network except npm install.
- **Deployed site:** HTTPS static hosting. Browser loads same-origin:
  - `index.html`, `gate.js`, `gate.css`, `gate-config.json`
  - optional `enroll.html`, `enroll.css`, `enroll-*.js`
- **connect-src `'self'`** on gate (config fetch). Enroll uses `connect-src 'none'`.
- No application server, no WebSocket, no third-party script hosts under the recommended CSP.

## Security Architecture

### Cryptographic design

| Element | Purpose |
|---------|---------|
| `K` (32 B) | AES-GCM content key, random per build |
| `share1` / `share2` | `K = share1 ⊕ share2`; `share1` published; `share2` only via mask recovery |
| `mask` | `hash ⊕ share2` per enrollee |
| PBKDF2 salt | `randomSalt ‖ UTF-8(pageId)` — page-scoped |
| PRF salt | `UTF-8("circle-prf:v1:" + pageId)` — page-scoped, origin-bound credential |

### CSP (strict)

Gate loader meta (and recommended HTTP header):

```
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'
```

Same-origin static assets only. No `'unsafe-inline'`, no nonces.

### Credential isolation

| Secret | Build | Git | CDN |
|--------|-------|-----|-----|
| Clear HTML | Input | Should not ship in dist | Ciphertext only |
| Enroll hashes | `hashes/` | Keep private | Never |
| `K` / `share2` | Ephemeral | Never | Never (only share1 + masks) |
| Passwords | Never stored | Never | Never |

### Auth matrix

| Actor | Capability |
|-------|------------|
| Operator with hashes | Build unlockable dist |
| Visitor with correct password/PRF | Decrypt in browser |
| Anonymous CDN client | Download ciphertext + masks; offline attack on PBKDF2 entries |
| Holder of hash + mask | Recover share2 → K if they also have share1 (i.e. published config) — **do not leak hashes** |

## Design Decisions

| Decision | Rationale | Rejected |
|----------|-----------|----------|
| Client-side gate | Static hosting, no backend | Server session auth |
| XOR mask with enroll hash | No password in build output | Embedding verifier only without offline cost tradeoff |
| External gate.js/css | Strict CSP | Inline script loaders |
| Depend on circle-enroll | Single enroll implementation | Duplicated enroll sources |
| pageId binding | Cross-site password reuse ≠ cross-site unlock | Global hashes |
