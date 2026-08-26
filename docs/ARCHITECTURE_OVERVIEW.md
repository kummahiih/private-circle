# Architecture Overview — @kummahiih/private-circle

## Overview

`@kummahiih/private-circle` builds **static, client-gated** HTML sites. Clear content is encrypted at build time (AES-256-GCM). The published site ships ciphertext, XOR masks derived from enrollment hashes, and a small loader. Unlock happens entirely in the browser via password (PBKDF2) or WebAuthn PRF. Enrollment UI assets are supplied by `@kummahiih/circle-enroll`.

## System Components

| Component | Path | Role |
|-----------|------|------|
| CLI | `bin/cli.mjs` | `encrypt`, `init` |
| Encrypt core | `src/encrypt-page.mjs` | Load hashes, encrypt content, write dist |
| Hash loader | `src/load-hashes.mjs` | Validate enroll JSON (PBKDF2 / PRF) |
| Loader builder | `src/build-loader.mjs` | Static `index.html` shell + gate-config shape |
| Utils | `src/util.mjs` | pageId normalize, XOR, salts |
| Public API | `src/index.mjs`, `src/encrypt.mjs` | Package exports |
| Gate runtime | `assets/gate.js`, `assets/gate.css` | Browser unlock UI + crypto |
| Enroll (dep) | `@kummahiih/circle-enroll` | enroll.html/css/js resolved at runtime |
| Tests | `test/encrypt.test.mjs` | Unit + integration |
| Publish | `.github/workflows/publish.yml` | npm publish |

## Data Flow

### Build (trusted operator machine)

1. Collect enroll JSON files into `hashes/` (from circle-enroll).
2. `encrypt --page-id P --content clear.html --hashes hashes --out dist`
3. Generate random content key `K`, split `K = share1 ⊕ share2`.
4. For each enroll hash `H`: publish `mask = H ⊕ share2` (and salt for PBKDF2).
5. AES-GCM encrypt clear HTML with `K`; write `gate-config.json` with `share1`, `iv`, `cipher`, `entries`.
6. Copy `gate.js`, `gate.css`; copy enroll assets from circle-enroll if available.

### Runtime (visitor browser)

1. Load `index.html` → `gate.js` → fetch `gate-config.json` (same origin).
2. Password: PBKDF2 → candidate `H'` → try `K' = share1 ⊕ (H' ⊕ mask)` → decrypt.
3. PRF: WebAuthn get with page-scoped salt → same XOR path.
4. On success, replace document with decrypted HTML.

## Technology Stack

- Node.js ≥ 18 (build), Web Crypto + WebAuthn (browser)
- AES-256-GCM, PBKDF2-SHA256 (310000 iterations), WebAuthn PRF
- ESM package; Apache-2.0

## Tool / Integration Architecture

- **npm dependency:** `@kummahiih/circle-enroll` for enroll assets
- **Consumers:** hello-circle and any static host (Vercel `outputDirectory: dist`)
- **Interfaces:** CLI argv; `encryptPage()` options object

## Workspace / Package Boundary

Published files: `bin/`, `src/`, `assets/` (gate*), templates if present. Enroll canonical sources live in circle-enroll; local `assets/enroll*` may remain as fallback only.
