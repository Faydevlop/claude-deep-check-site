---
name: deep-check-site
description: Deep security reconnaissance of a live website from a link — maps the backend, inspects HTTP security headers, scans public JS bundles for exposed secrets (Firebase/Supabase config, hardcoded admin emails, API keys), reviews auth/authorization behavior, cookies and TLS, then writes a prioritized findings report. Use when the user gives a URL and asks to "check", "audit", "analyze", "scan", "security review", or "deep check" a site. Authorized/defensive testing only (your own site or one you have written permission to test).
---

# Deep Check Site

A structured, mostly-passive security assessment of a live website, driven from a single
URL. It favors manual, observable evidence over automated scanners: read what the site
actually ships to the browser, reason about the backend it exposes, and report concrete,
reproducible findings.

## Scope and authorization — read first

This skill performs **active requests against a live target**. Only proceed when at least one
of these is true, and say which in the report:

- The target is owned by the user, or
- The user has written permission / an engagement to test it, or
- It is a dedicated lab / CTF / intentionally-vulnerable target.

**Hard limits — never do these**, regardless of authorization, unless the user explicitly
asks and it is clearly in-scope:

- No denial-of-service, load/stress testing, or high-volume brute force.
- No destructive writes to real user data. If a write-access test is needed, use a
  throwaway account and revert immediately, recording the before/after.
- No testing of third-party sites, other tenants, or infrastructure you weren't scoped for.
- No exfiltration of real users' personal data beyond the minimum needed to prove a finding
  (a count and 1–2 redacted samples, not a full dump).

If authorization is unclear, ask once before sending any request. If the user can't confirm
ownership/permission, stop and explain why.

## What you need from the user

- The target URL (required).
- Whether they can test as a signed-in user, and if so, test credentials or a throwaway
  account they're OK using (many of the highest-impact checks need an authenticated session).
- Confirmation of authorization (above).

## Workflow

Work through these phases in order. Skip a phase only when it doesn't apply (e.g. no backend
API is reachable), and note the skip in the report.

### 1. Recon — what is this thing?

- Load the site and note the stack: framework (React/Vue/Next/etc.), hosting/CDN, and
  especially the **backend**. Look in the page source and network traffic for tell-tale
  domains and config:
  - Firebase / Firestore: `firebaseapp.com`, `firestore.googleapis.com`, a `firebaseConfig`
    object with `apiKey`, `projectId`, `authDomain`.
  - Supabase: `*.supabase.co`, an `anon` key (a JWT), `supabase.co/rest/v1`.
  - Appwrite, AWS Amplify/Cognito, Pocketbase, a custom REST/GraphQL API, etc.
- Enumerate the JS bundles the site loads. The main `index-*.js` / vendor bundle is where
  secrets and logic leak. Note their URLs for the next phase.
- See `references/recon.md` for backend fingerprints and where each one typically leaks.

### 2. Public JS bundle analysis (no login required)

Everything a visitor's browser downloads is public. Fetch the bundles and grep them for:

- **Hardcoded secrets & identities**: admin email allowlists, private API keys/tokens,
  signing secrets, hardcoded salts/IVs, third-party service keys (Stripe, SendGrid, Maps,
  OpenAI, etc.). A publicly-shipped admin-email check is a classic finding — it leaks a staff
  identity and proves there's no real server-side role system.
- **Client-side authorization logic**: code that decides admin/role/paid status in the
  browser (`isAdmin = [...].includes(email)`, `role === 'business_owner'`). Anything the
  client *decides* is something the backend probably *doesn't enforce* — flag it and test the
  backend directly in phase 4.
- **Encryption done wrong**: hardcoded/shared salts, keys derived on the client, private key
  material that round-trips through the server.

`scripts/scan_bundle.py <url-or-file>` downloads a bundle (or reads a saved one) and runs a
battery of regexes for the patterns above. Treat every hit as a *lead* to verify by hand, not
a confirmed finding.

### 3. HTTP security headers & transport

- Fetch the main document response and record which protective headers are present or
  **absent**: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` (or
  CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`.
- Check cookies for `Secure`, `HttpOnly`, `SameSite`.
- Note TLS: is HTTP redirected to HTTPS? Is HSTS set (and preloaded)?
- `scripts/check_headers.py <url>` prints a present/absent table for all of the above.
- Absent headers are **defense-in-depth / medium** findings on their own — don't over-rate
  them, but a site missing all of them signals little security review.

### 4. Authentication & authorization (the high-impact phase)

This is where the critical findings usually live. With an **authorized, authenticated**
session:

- **Broad read access / IDOR**: can a normal user read records that aren't theirs? For
  Firestore, try listing a collection (`/v1/projects/<id>/databases/(default)/documents/<col>`)
  with your own bearer token — if it returns *other* users' documents, the security rules are
  too open. For REST/GraphQL APIs, change an ID in a request to one you don't own.
- **Sensitive fields in readable records**: once a collection is readable, note what's inside
  — emails, phones, tokens, private keys, internal flags.
- **Privilege / tier escalation via self-write**: can a user write fields on their own record
  that the app treats as privileged (`role`, `accountType`, `isVerified`, `plan`)? Test with a
  throwaway account, confirm the app honors it, and **revert immediately**.
- **Moderation/admin data exposure**: reports, audit logs, support tickets readable by normal
  users.
- **Account deletion actually deletes**: create a throwaway account, delete it via the app's
  own flow, then query the backend directly to confirm the data is gone (a "right to erasure"
  gap if it isn't).
- `references/firestore.md` has ready-to-adapt Firestore request shapes; `references/authz.md`
  covers the generic IDOR/self-write playbook for any backend.

### 5. Auth hygiene (lighter-weight checks)

- Password policy: minimum length, complexity, breach/common-password rejection.
- Brute-force friction at the **app** layer (lockout, CAPTCHA, backoff) — note what the
  platform (e.g. Firebase Auth) provides vs. what the app adds.
- Account-existence leaks in login / password-reset / signup responses.
- Session handling: does sign-out clear the session; token lifetime/refresh behavior.

### 6. Input handling (spot checks, non-destructive)

- Stored XSS in the obvious user-controlled, user-visible fields (display name, post/comment
  body): submit an inert marker payload and check whether it renders as **escaped text**
  (good) or executes (finding). Keep payloads inert and clean them up.
- Open redirects in `redirect`/`next`/`return` params.
- Note, don't exploit, anything that looks like SQL/NoSQL injection — report it as a lead.

## Writing the report

Produce a single Markdown report. Structure it like this:

1. **Header block**: target, backend, access level tested, date, and the authorization basis.
2. **Summary line**: counts by severity (e.g. `3 Critical · 4 High · 2 Medium · 1 Low`).
3. **A short orienting note** when something needs context (e.g. "the Firebase API key in the
   bundle is *not* itself the vulnerability — the Firestore rules are").
4. **Findings, grouped by severity**, each with: *Where* (exact location/endpoint),
   *Evidence* (a real, reproducible request/response or code snippet, with personal data
   redacted), and *Why it matters* (the concrete real-world impact, in plain language).
5. **"Also checked — working as intended"**: the things that were *not* vulnerable. This is
   not filler — it shows the review was thorough and tells the owner what already holds.
6. **Method & test-data notes**: that it was manual, what account(s) were used, any write that
   was made and reverted, and any residue left behind (e.g. an orphaned record) with its path.

Severity guidance:
- **Critical** — anyone can read/alter data platform-wide, or escalate privilege, with no
  special access (e.g. open Firestore read rules exposing all users; self-granted admin).
- **High** — leaked staff identity / admin surface, moderation data exposure, "delete doesn't
  delete".
- **Medium** — weak password policy, missing security headers, missing app-level brute-force
  friction.
- **Low** — silent validation failures, minor UX-as-security papercuts.

Always write evidence someone can **reproduce**. A finding without a concrete request,
response, or code excerpt is a guess, not a finding. Redact other people's personal data in
every snippet.

## Style

- Be precise and non-alarmist. Rate impact by what an attacker can actually do, not by how
  scary a header name sounds.
- Prefer showing over telling: a two-line request that returns someone else's data is worth
  more than a paragraph of theory.
- Keep the owner's audience in mind — explain *why it matters* without jargon.

## Optional: a client demo guide

If the user wants to *show* a non-technical owner the issues live, offer to also produce a
"demo guide": a short script of DevTools-console / Network-tab steps, each self-contained,
each labeled read-only vs. data-changing (with an undo step), and each with a plain-English
line to say. See `references/demo-guide.md` for the format.
