# @kummahiih/private-circle

Ship a **static** site that stays unreadable until the visitor enters a matching password **or** unlocks with a WebAuthn passkey (PRF).

- Passwords / passkeys never need to live in git
- Hashes are **page-scoped** via `pageId`
- Build-time AES-256-GCM + XOR masks
- Same-origin enrollment page for PRF support
- **Strict CSP** friendly (no inline scripts)

## Install

```bash
npm i -D @kummahiih/private-circle
# or just use npx
```

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

Use the included `enroll.html` (copied by `init` or by the encrypt step when present).

- **Password** → `alg: "PBKDF2-SHA256"`
- **Passkey (WebAuthn PRF)** → `alg: "WebAuthn-PRF"`  
  Must be enrolled on the **same origin** as the gated page.

See `assets/enroll-json.md` for the exact JSON format.

## Strict CSP

The gated page ships **without inline scripts or styles**:

| File | Role |
|------|------|
| `index.html` | Shell only |
| `gate.js` | Unlock logic (`script-src 'self'`) |
| `gate.css` | Styles (`style-src 'self'`) |
| `gate-config.json` | Per-build secrets (`connect-src 'self'`) |

Default meta CSP on the loader:

```
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; ...
```

Enroll page uses the same pattern (`enroll.html` + `enroll-core.js` + `enroll-prf.js`).

## Tests

```bash
npm test
# or
node --test test/*.mjs
```

## Security notes

- Client-side gate only. Weak passwords can be guessed offline against the downloaded ciphertext + masks.
- WebAuthn PRF greatly reduces the offline attack surface (authenticator required).
- Keep `hashes/` private. Never publish both hash and mask.
- Passkey loss = permanent lockout unless you keep a password backup enrollment.
