# @kummahiih/private-circle

Ship a **static** site that stays unreadable until the visitor enters a matching password **or** unlocks with a WebAuthn passkey (PRF).

- Passwords / passkeys never need to live in git
- Hashes are **page-scoped** via `pageId`
- Build-time AES-256-GCM + XOR masks
- Same-origin enrollment (from `@kummahiih/circle-enroll`) for PRF support
- **Strict CSP**: same-origin static assets only (`script-src` / `style-src` `'self'`)

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
