# Ethics review — @kummahiih/private-circle

**Subject:** `kummahiih/private-circle` (npm `@kummahiih/private-circle` 0.3.3) plus intended use by operators of gated static sites (`hello-circle` and forks).
**Date:** 2026-08-31
**Scope:** Whole subject repo. Not an IRB letter, lawyer memo, threat model, or permission to ship secrets.
**Stance:** Issues listed with live tensions. No single moral theory is treated as decisive.

Related artifacts read: `README.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE_OVERVIEW.md`, `docs/AI_DISCLOSURE.md`, `assets/security.md`, enroll JSON notes. Threat rows are not copied here.

## Stakeholders

| Party | Role |
|-------|------|
| Package maintainers | Publish methods and defaults |
| Site operators | Collect enroll JSON, hold cleartext, choose host and passwords |
| Circle members | Send hashes / use passkeys; may put life facts on the page |
| Excluded visitors | See a locked shell; cannot consent to being left out |
| Host / CDN / npm | Carry ciphertext, masks, and package code |
| People named in content | May never see the page or the gate |

Who cannot consent: minors on family pages; third parties described in operator HTML; future inheritors of a lockout; platforms that only see ciphertext.

## Checklist (from the artifact)

- [x] Human subjects / identifiable data — not a research protocol; operator HTML can still hold unpublished identifiable facts
- [ ] Animals / organoids
- [x] Deception or covert recording — locked shell + robots.txt can hide that a circle page exists; not covert *recording*, but covert *presence*
- [x] Dual-use — public client-side concealment methods (see E1)
- [ ] Self-experiment framed as a protocol
- [x] Minors — plausible family use; package does not bar it
- [x] Publication of unpublished personal data — ciphertext on a public CDN is still a publication of *something*
- [x] Conflict — author-adjacent review of own pack; this file is not a self-grade of crypto quality
- [ ] Environmental / waste wet protocol
- [x] Attribution — Apache-2.0 + `docs/AI_DISCLOSURE.md`; pre-1.0 human review still open

## Issue table

| ID | Tension | Who is affected | Consent? | Dual-use? | Severity | Control | Open? |
|----|---------|-----------------|----------|-----------|----------|---------|-------|
| E1 | Small-circle opacity vs concealment of harmful or illegal content with no server audit | Public, hosts, possible victims; operators who thought they only built a family page | Hosts and victims do not consent to how third parties reuse the package | Yes | High | Name intended use (small trusted circle). Do not document concealment of abuse, weapons, or exploitation. Hosts keep their own AUP. This review does not supply misuse methods. | Yes |
| E2 | Calling the site “private” vs honest residual risk (offline guess of weak passwords against public ciphertext + masks) | Members who share health, money, or location facts | Members often consent to a password, not to the threat model | No | High | README / security.md already deny server-grade auth. Threat model still leaves “treat weak-password circles as public-readable” unchecked. Enroll UI should say the same in member language. | Yes |
| E3 | Operator must hold hashes and cleartext to build vs members treating the operator as a peer | Members; operator | Partial: they send JSON; they may not know the operator can add extra unlock entries or keep hashes | No | Medium | Document: operator can always read. Vault or delete `hashes/` after deploy. Never commit real hashes. | Residual |
| E4 | Passkey convenience vs device-bound unlock secret sitting in operator-held enroll JSON | PRF users | WebAuthn prompt is thin consent; PRF hash is not a biometric but is authenticator-bound | Low | Medium | Same-origin enroll; vault hashes; password backup if recovery is required | Residual |
| E5 | Family coordination vs children who cannot consent to photos or notes behind a weak gate | Minors; guardians | No for the child | Possible if content is exploitative (stop; do not specify) | Medium | Operator rule: no unpublished identifiable minors on a page that is only casually gated. Prefer PRF + strong backup. | Yes |
| E6 | robots.txt / empty shell vs people who have a claim to know the page exists | Excluded kin, counterparties, indexers | No | Adjacent to E1 | Medium | State that robots.txt stops crawlers, not that the URL is a secret. Do not present the pack as a hidden-service kit. | Yes |
| E7 | Ship useful crypto now vs members relying on pre-1.0 AI-assisted code for high-stakes secrets | Operators, members | Disclosure exists if they read it | No | Medium | `docs/AI_DISCLOSURE.md` + pre-1.0 warning. Independent review before calling the pack production-high-security. | Yes until 1.0 |
| E8 | Open Apache-2.0 methods vs downstream commercial or high-risk reuse the authors cannot see | Downstream users; authors | License is consent to reuse code, not to authors’ duty of care for every fork | Yes (same as E1) | Low | License + npm semver; pin versions; Hobby-host limits stay the operator’s problem | Residual |
| E9 | PRF-only lockout (strong secrecy) vs duty not to brick members’ own shared material | Members, operator | Weak after the fact | No | Low | Documented password-backup enrollment | Residual |

## Dual-use row (required)

This repo is a **public methods note** for client-side AES-GCM gating. The same controls that keep a small circle off search indexes can hide content hosts and the public cannot inspect. That is ordinary cryptography dual-use, not a weapons protocol.

- **In scope to say:** the pack is for trusted small circles; it is not access control; weak passwords make the page public to anyone who downloads `dist/`.
- **Out of scope:** how to hide illegal material, evade platform review, or run covert ops. If a request asks for those methods, refuse; do not ethics-wash them with this file.

## Already mitigated (do not re-litigate as ethics)

These are engineering controls, recorded so ethics does not copy the threat model:

- No passwords in git; `pageId`-scoped hashes; encrypt refuses weak PBKDF2 iterations and `hashes/` inside `dist/`
- New `K` per rebuild; AES-GCM IV collision fail-closed
- Strict CSP documentation; generic unlock failure text
- AI use disclosed; Apache-2.0 attribution path exists

## Open before the next public write that claims “private”

1. **E2:** User-facing enroll / gate copy that weak-password pages are offline-guessable.
2. **E1:** One paragraph acceptable-use in README (small circle; not a drop for material the operator would not put on an unlocked site).
3. **E5:** Explicit “minors / identifiable photos” sentence in operator runbook.
4. **E7:** Keep the 1.0 human-review gate; do not raise security language before it.

## What this file is not

Not approval to put medical files, children’s photos, or unpublished third-party data on a static host. Not a finding that the crypto is sound. Not a finding that it is unsound. Re-open if the pack adds server-side identity, analytics on unlock, or a public hash directory.
