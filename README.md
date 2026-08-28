# @kummahiih/private-circle

Ship a **static** site that stays unreadable until the visitor enters a matching password **or** unlocks with a WebAuthn passkey (PRF).

- Passwords / passkeys never need to live in git
- Hashes are **page-scoped** via `pageId`
- Build-time AES-256-GCM + XOR masks
- Same-origin enrollment (from `@kummahiih/circle-enroll`) for PRF support
- **Strict CSP**: same-origin static assets only (`script-src` / `style-src` `'self'`)

## AI Disclosure

This package has been developed with assistance from artificial intelligence tools. Users and developers should be aware that portions of the code, documentation, and implementation may have been generated or refined using AI-assisted development practices.

## Install

```bash
npm i -D @kummahiih/private-circle
```

Depends on `@kummahiih/circle-enroll` for enroll UI assets.

## Quick start

```bash
npx @kummahiih/private-circle init
# edit content/index-plaintext.html
# collect enroll JSON files into hashes/
npx @kummahiih/private-circle encrypt \
  --page-id my-site \
  --content content/index-plaintext.html \
  --hashes hashes \
  --out dist
```

## CLI

```
private-circle encrypt --page-id <id> --content <file> --hashes <dir> --out <dir>
private-circle init [--dir <path>]
```

## Programmatic API

```js
import { encryptPage, loadHashes } from '@kummahiih/private-circle';

encryptPage({
  pageId: 'my-site',
  content: 'content/index.html',
  hashes: 'hashes',
  outDir: 'dist',
});
```

## Enrollment

Enroll assets come from `@kummahiih/circle-enroll` (`init` / encrypt resolve the package path):

- **Password** → `alg: "PBKDF2-SHA256"`
- **Passkey (WebAuthn PRF)** → `alg: "WebAuthn-PRF"` (same origin as the gated page)

See package `enroll-json.md` for the exact JSON format.

PBKDF2 enroll JSON **must** use `iterations >= 310000`. Encrypt refuses weaker parameters.

**Browser / authenticator matrix for PRF:** [docs/WEBAUTHN_PRF_SUPPORT.md](docs/WEBAUTHN_PRF_SUPPORT.md) (Chrome/Edge 116+, Safari 18+, Firefox 135+; platform authenticators vary).

## Operator runbook (production)

1. **Same-origin enroll for PRF** — Serve `enroll.html` on the **same origin** as the gated page. WebAuthn RP ID binds the passkey; cross-origin public enroll works for PBKDF2 only.
2. **Prefer WebAuthn-PRF** for high-value circles. Keep a **password backup** enrollment if recovery after authenticator loss is required (passkey-only = permanent lockout on loss).
3. **Hashes hygiene** — Never commit real `hashes/` to public git; never ship `hashes/` inside `dist/`. Vault or delete after deploy. Demo sites may keep labeled public demo hashes only.
4. **Rotate on leak** — If any hash set may have leaked with published masks, rotate build key `K`, re-encrypt, and re-enroll everyone.
5. **HTTP headers (critical)** — The host must set correct `Content-Type` and CSP. A wrong type (e.g. `gate.js` as `text/plain`) can defeat CSP assumptions.

```
gate.js            Content-Type: application/javascript
gate.css           Content-Type: text/css
gate-config.json   Content-Type: application/json
index.html         Content-Type: text/html; charset=utf-8
enroll.html        Content-Type: text/html; charset=utf-8
enroll.css         Content-Type: text/css
enroll-*.js        Content-Type: application/javascript
all responses      Content-Security-Policy: default-src 'none'; … (match loader meta; no 'unsafe-inline')
```

See also [`assets/security.md`](assets/security.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and [`@kummahiih/circle-enroll` README](https://github.com/kummahiih/circle-enroll).

## Hashes hygiene

| Rule | Why |
|------|-----|
| **Never commit real `hashes/`** to public git | Enroll JSON + published mask ⇒ direct recovery of build key `K` |
| **Never ship `hashes/` inside `dist/`** | Encrypt consumes hashes at build; dist is public CDN material |
| Vault or delete `hashes/` after deploy | Limits laptop / backup exposure |
| Rotate `K` + re-enroll if hashes may have leaked | Invalidates old masks |

Demo sites (e.g. hello-circle) may keep **labeled public demo hashes** only. Production circles must keep enroll JSON private.

`encryptPage` refuses a dist that already contains a `hashes/` directory and scans text files for obvious plaintext markers when provided.

## Strict CSP

**Same-origin static files only** — no inline scripts/styles, no nonces, no third-party hosts.

| File | Role | CSP |
|------|------|-----|
| `index.html` | Shell only | no executable code |
| `gate.js` | Unlock logic | `script-src 'self'` |
| `gate.css` | Styles | `style-src 'self'` |
| `gate-config.json` | Per-build secrets | `connect-src 'self'` |
| `enroll.html` + `enroll.css` + `enroll-*.js` | Enrollment | same pattern; enroll meta uses `connect-src 'none'` |

Default meta CSP on the gate loader:

```
default-src 'none'; base-uri 'none'; form-action 'none';
script-src 'self'; style-src 'self'; connect-src 'self';
img-src 'none'; font-src 'none'; object-src 'none'; frame-ancestors 'none'
```

Recommended HTTP header (e.g. Vercel) should match. Do not add `'unsafe-inline'`.

## Tests

```bash
npm test
```

## Security notes

- Client-side gate only. Weak passwords can be guessed offline against downloaded ciphertext + masks.
- WebAuthn PRF reduces the offline attack surface (authenticator required).
- Keep `hashes/` private. Never publish both enroll `hash` and published `mask`.
- Passkey loss = permanent lockout unless you keep a password backup enrollment.

## License

Apache-2.0
