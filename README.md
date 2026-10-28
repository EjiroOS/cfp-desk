# cfp-desk

A small call-for-proposals (CFP) app for community events: speakers create an account, fill in a profile, and write talk proposals as drafts or submissions.

> ℹ️ **main is the fixed version.** The original, deliberately vulnerable code is on the `vulnerable` branch. Run either version on your own machine only, never on a network.

## Why I built this

I coordinate calls for proposals for community events, so I've seen how much speakers share when they submit: their talk ideas, their bios, their contact details. I built this small CFP app to learn how attackers could expose that information, and how to stop them.

## Findings

| # | Finding | OWASP 2025 | Severity | Status |
|---|---|---|---|---|
| 1 | [IDOR on proposals](findings/01-idor-proposals.md) | A01 Broken Access Control | Medium | ✅ Fixed |
| 2 | [SQL injection login bypass](findings/02-sqli-login.md) | A05 Injection | Critical | ✅ Fixed |
| 3 | [Stored XSS in abstracts](findings/03-stored-xss.md) | A05 Injection | High | ✅ Fixed |
| 4 | [Unsalted MD5 passwords](findings/04-weak-password-hashing.md) | A04 Cryptographic Failures | High | ✅ Fixed |
| 5 | [Insecure cookie, no security headers](findings/05-insecure-cookie-headers.md) | A02 Security Misconfiguration | Medium | ✅ Fixed |

## Progress

- [x] 1. Build the vulnerable app
- [x] 2. Attack it and write up findings
- [x] 3. Fix every issue, with before/after evidence
- [ ] 4. DevSecOps pipeline (SAST, secrets, SCA, container and DAST scans)
- [ ] 5. Supply chain security (SBOM, Sigstore signing, SLSA provenance)

## Running it

You need Docker.

    docker compose up --build

Then open http://127.0.0.1:8080. Stop it with Ctrl+C, then run `docker compose down`.

### Test accounts (all fake)

| Username | Password |
|---|---|
| amara | sunshine1 |
| kofi | password123 |

## Built with

Go, SQLite, Docker.

Built with help from Claude as a learning aid. I carried out the attacks, wrote the findings, and made the fixes myself.
