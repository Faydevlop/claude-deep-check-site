# OWASP Top 10 (2021) — scorecard mapping

Every report must end with an **OWASP Top 10 scorecard**: for each of the ten categories, give
a verdict and one line of evidence. Use exactly these verdicts:

- **Followed** — tested and the control holds.
- **Not followed** — tested and a real weakness was found (link to the finding above).
- **Partial** — some controls present, others missing.
- **Not tested** — out of scope / no authorized access / not reachable in this pass. Say why;
  never guess a pass.

Render it as a table:

| # | Category | Verdict | Evidence / note |
|---|----------|---------|-----------------|
| A01 | Broken Access Control | Not followed | Any signed-in user can read all `users` records (Finding 1) |
| ... | ... | ... | ... |

## What maps to each category

**A01 — Broken Access Control.** The highest-value category here. IDOR, broad-read database
rules, privileged self-writes / mass assignment, missing function-level checks, "delete
doesn't delete", moderation/admin data readable by normal users. → phase 4 + `authz.md`.

**A02 — Cryptographic Failures.** Secrets/keys shipped to the client, private key material
stored server-side or round-tripped, hardcoded or shared salts/IVs, weak/absent TLS, missing
HSTS, sensitive data sent or stored in clear. → bundle scan + headers + field inspection.

**A03 — Injection.** Stored/reflected XSS (is user input rendered escaped or executed?),
SQL/NoSQL injection leads, open redirects, template injection. Spot-check non-destructively;
report injection *leads* without exploiting. → phase 6.

**A04 — Insecure Design.** Design-level gaps: no real role system (admin decided client-side
by an email list), no rate-limit/anti-automation design, trust boundaries that assume the
client enforces rules. → inferred from bundle logic + auth behavior.

**A05 — Security Misconfiguration.** Missing security headers, permissive CORS, default
credentials, verbose errors/stack traces, directory listing, debug endpoints left on,
over-permissive managed-backend rules at the config level. → `check_headers.py` + recon.

**A06 — Vulnerable and Outdated Components.** Known-vulnerable JS libraries/framework versions
disclosed in bundles or headers, outdated server banners. Note versions you can see; flag
obviously old/CVE-bearing ones. (Do not run exploit code.)

**A07 — Identification and Authentication Failures.** Weak password policy, no brute-force
friction at the app layer, account-existence leaks (login/reset/signup), weak session
handling, tokens with excessive lifetime, sign-out that doesn't clear the session. → phase 5.

**A08 — Software and Data Integrity Failures.** Scripts loaded from third parties without
Subresource Integrity (SRI), unsigned/untrusted update or deserialization paths, CI/CD or
dependency trust assumptions visible from the client. → check `<script>`/`<link>` tags for SRI.

**A09 — Security Logging and Monitoring Failures.** Hard to prove from outside, but note
observable signals: no audit trail behind privileged actions, client-only "admin" with no
server record, no evidence of alerting on the abuse you demonstrated. Usually **Not tested**
unless the owner shares backend visibility — say so.

**A10 — Server-Side Request Forgery (SSRF).** Any feature where the server fetches a
user-supplied URL (link preview, webhook, image-from-URL, import). Note the surface; probe for
SSRF only if explicitly in scope and non-destructively. Often **Not tested**.

## Rules for the scorecard

- A verdict needs evidence. "Followed" means you *checked* and it held — not that you didn't
  look. If you didn't look, it's **Not tested**.
- Cross-link: every **Not followed** / **Partial** row points to the detailed finding above.
- Prefer honesty over coverage: a scorecard full of **Not tested** with reasons is more useful
  than invented passes.
