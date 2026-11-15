# deep-check-site

A [Claude](https://claude.com/claude-code) **skill** for a deep, mostly-passive security
assessment of a live website — driven from a single URL.

Give Claude a link and it maps the backend, inspects HTTP security headers, scans the public
JavaScript bundles for leaked secrets (Firebase/Supabase config, hardcoded admin emails, API
keys), reviews authentication and authorization behavior, checks cookies and TLS, and writes a
**prioritized, reproducible findings report** — then, optionally, a live demo guide you can walk
a non-technical owner through in their own browser.

It favors manual, observable evidence over automated scanners: read what the site actually
ships to the browser, reason about the backend it exposes, and report concrete findings with
real request/response evidence.

## ⚠️ Authorized / defensive use only

This skill makes **active requests against a live target**. Only use it on:

- a site **you own**, or
- a site you have **written permission** to test, or
- a dedicated lab / CTF / intentionally-vulnerable target.

It will not run denial-of-service or high-volume brute force, will not destructively modify
real user data (write tests use throwaway accounts and are reverted), and keeps data access to
the minimum needed to prove a finding. Testing a site without authorization may be illegal.
You are responsible for staying in scope.

## What it checks

| Phase | Looks for |
|-------|-----------|
| **Recon** | Stack & backend fingerprint (Firebase, Supabase, Amplify, custom API), JS bundles |
| **Bundle analysis** | Hardcoded secrets, admin-email allowlists, client-side auth/role logic, crypto done wrong |
| **Headers & transport** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie flags, HTTPS |
| **AuthN / AuthZ** | Broad-read rules & IDOR, sensitive fields, privilege/tier self-escalation, moderation-data exposure, "delete doesn't delete" |
| **Auth hygiene** | Password policy, brute-force friction, account-existence leaks, session handling |
| **Input handling** | Stored-XSS spot checks, open redirects (non-destructive) |

## Install

Clone into your Claude skills directory so Claude can discover it:

```bash
# user-level (all projects)
git clone https://github.com/Faydevlop/claude-deep-check-site.git \
  ~/.claude/skills/deep-check-site

# or project-level
git clone https://github.com/Faydevlop/claude-deep-check-site.git \
  .claude/skills/deep-check-site
```

On Windows (PowerShell):

```powershell
git clone https://github.com/Faydevlop/claude-deep-check-site.git `
  "$env:USERPROFILE\.claude\skills\deep-check-site"
```

## Use

In Claude Code, just ask — the skill triggers on requests like:

> "Deep check https://my-app.example.com for security issues"
> "Audit the security of my site at example.com, I own it"

Claude will confirm authorization, then work through the phases and produce the report.

### The helper scripts (standalone, no dependencies)

```bash
# Present/absent table of security headers, cookie flags, HTTPS behavior
python scripts/check_headers.py https://example.com

# Scan a JS bundle for leaked secrets & client-side auth logic (every hit is a lead to verify)
python scripts/scan_bundle.py https://example.com/assets/index-abcd1234.js
```

## Layout

```
SKILL.md                  # the skill: scope, workflow, reporting format
references/
  recon.md                # backend fingerprints and where each one leaks
  firestore.md            # ready-to-adapt Firestore request shapes
  authz.md                # generic IDOR / self-write playbook (any backend)
  demo-guide.md           # format for a live, non-technical demo walkthrough
scripts/
  check_headers.py        # HTTP security-header & cookie checker
  scan_bundle.py          # JS-bundle secret/auth-logic scanner
```

## License

MIT — see [LICENSE](LICENSE).
