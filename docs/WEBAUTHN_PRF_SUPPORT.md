# WebAuthn PRF support matrix

The `prf` extension (WebAuthn Level 3) lets a passkey derive a stable secret used by private-circle as the enroll hash (`alg: "WebAuthn-PRF"`). Support depends on **both** the browser and the authenticator.

Snapshot: **2026-08**. Sources: W3C WebAuthn L3, Chromium/Firefox release notes, Corbado / nosskey summaries. Verify on target devices before relying on PRF-only enrollments.

## Browser (client)

| Browser | Min version (stable) | Notes |
|---------|----------------------|--------|
| Chrome / Edge / other Chromium | **116+** | PRF on get; platform + security keys. PRF-on-create with Windows Hello from ~147. iCloud Keychain PRF on macOS from ~132. |
| Safari | **18+** (macOS 15 / iOS 18 / iPadOS 18) | Platform authenticator (iCloud Keychain). **No** PRF to external CTAP2 security keys. |
| Firefox | **135+** (default on) | Create-time PRF backports in later trains; Windows Hello PRF more complete ~148+. Firefox for Android: limited / not reliable for PRF. |

## Platform authenticators

| Authenticator | Typical environment | PRF |
|---------------|---------------------|-----|
| Google Password Manager | Android 14+, Chrome 116+ | Yes |
| iCloud Keychain | macOS 15+, iOS/iPadOS 18+, Safari 18+ / Chrome 132+ | Yes (platform only) |
| Windows Hello | Windows 11 with hmac-secret support (broader after 2026 platform updates) | Browser-dependent; prefer recent Chrome/Edge 147+ or Firefox 148+ |

## Roaming authenticators (security keys)

| Setup | PRF |
|-------|-----|
| Chromium + CTAP2 key with `hmac-secret` | Yes |
| Safari + external security key | No (PRF not exposed to roaming authenticators) |
| Firefox + CTAP2 key | Often yes when key supports hmac-secret; test the specific key |

## Operator guidance

1. **Same origin** — Enroll and gate must share RP ID (same registrable domain). Cross-origin public enroll is PBKDF2-only.
2. **Backup path** — Prefer at least one PBKDF2 enroll per user if permanent lockout on passkey loss is unacceptable.
3. **Test the matrix** — Before PRF-only circles, run enroll + unlock on the actual browser/OS/authenticator combinations your members use.
4. **Fail closed in UI** — Gate already hides PRF controls when the browser does not advertise support; still document limits for operators.

Related: [README operator runbook](../README.md#operator-runbook-production), [THREAT_MODEL.md](./THREAT_MODEL.md), [circle-enroll](https://github.com/kummahiih/circle-enroll).
