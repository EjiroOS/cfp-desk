# cfp-desk

A small call-for-proposals (CFP) app for community events: speakers create an
account, fill in a profile, and write talk proposals as drafts or submissions.

> ⚠️ **This branch is deliberately vulnerable.** It exists so I can practise
> finding, exploiting and fixing real web security bugs. Run it on your own
> machine only. Never deploy it or expose it to a network.

## Why I built this

I coordinate CFPs for community events, so I know how sensitive unpublished
talk proposals can be. This project asks: what happens when a CFP tool gets
security wrong, and how do you fix it and stop it happening again?

## Project plan

1. Build the vulnerable app ← *you are here*
2. Attack it and write up findings mapped to the OWASP Top 10
3. Fix every issue on a `secure` branch, with before/after evidence
4. Add a DevSecOps pipeline (SAST, secrets, SCA, container and DAST scans)
5. Add supply chain security (SBOM, Sigstore signing, SLSA provenance)

## Running it

You need Docker.

```sh
docker compose up --build
```

Then open http://127.0.0.1:8080. Stop it with `Ctrl+C`, then:

```sh
docker compose down
```

The app is published on `127.0.0.1` only, so nobody else on your network can reach it.

### Test accounts (all fake)

| Username | Password |
|---|---|
| amara | sunshine1 |
| kofi | password123 |

## Built with

Go (standard library `net/http` and `html/template`), SQLite, Docker.
