# Remediation catalog — the fix for each common finding

This skill is fix-first: every finding ships with its remediation. Pull concrete, correct fixes
from here and adapt them to the target. These are starting points — tell the owner to test them
against their own schema and flows before deploying.

## Broad-read / IDOR on a managed backend

**Firestore — scope reads (and field writes) to the owner:**

```
// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /users/{uid} {
      // a user reads/writes only their own document...
      allow read: if request.auth != null && request.auth.uid == uid;
      allow create: if request.auth != null && request.auth.uid == uid;
      // ...and may not touch privileged fields on self-update
      allow update: if request.auth != null && request.auth.uid == uid
        && !request.resource.data.diff(resource.data)
              .affectedKeys().hasAny(['role','accountType','isAdmin','plan','credits']);
    }
    match /reports/{id} {
      // moderation data: admins only
      allow read, write: if request.auth != null
        && get(/databases/$(db)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
  }
}
```

**Supabase — turn on RLS and scope with a policy:**

```sql
alter table public.users enable row level security;

create policy "owner reads own row"
  on public.users for select
  using ( auth.uid() = id );

create policy "owner updates own row, not privileged columns"
  on public.users for update
  using ( auth.uid() = id )
  with check ( auth.uid() = id );
-- keep role/plan columns out of the client-writable set (separate table or a trigger/guard).
```

**Custom REST/GraphQL — enforce object-level authz on the server:** on every read/write, compare
the resource's owner to the authenticated principal (`if (resource.ownerId !== req.user.id)
return 403`). Never rely on the client hiding the endpoint or the ID.

## Privileged fields / tier set from the client (mass assignment)

Decide `role` / `accountType` / `plan` **only on the server**, and never accept them from a
client-supplied body. Keep them in a record the client cannot write (admin-only collection, a
Firebase custom claim, a column guarded by RLS/trigger). The server, not the browser, is the
source of truth for who is an admin or a paid tier.

## Admin identity hardcoded in the client

Replace the shipped email allowlist with a real server-side role:
- Firebase: set a **custom claim** (`admin: true`) via the Admin SDK; check it in rules and on
  the server, never by comparing emails in bundled JS.
- Supabase/custom: an `is_admin` / `role` column checked server-side.
This removes the leaked staff email and gives you add/remove-without-redeploy plus an audit trail.

## Secrets in the client bundle

- A **public** key (Firebase web key, Supabase anon key) is fine to ship — don't rotate out of
  panic; fix the *rules* instead.
- A **real secret** (service key, `sk_live`, signing key, private key) must never reach the
  browser. Move it server-side (an API route / cloud function), **rotate the exposed secret
  immediately**, and call the third party from the server.

## Weak crypto (shared salt / client-held keys)

Use a **per-user random salt** (stored with the record), standard KDFs (Argon2id/scrypt/PBKDF2
with high iterations), and keep private keys **on the device** (or in a KMS) — never a single
hardcoded salt and never server-stored private keys that others can read.

## Missing security headers

**Express/Node — Helmet gives sane defaults:**

```js
const helmet = require('helmet');
app.use(helmet()); // CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy...
```

**Firebase Hosting / static — set them in `firebase.json`:**

```json
{ "hosting": { "headers": [
  { "source": "**", "headers": [
    { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },
    { "key": "X-Content-Type-Options", "value": "nosniff" },
    { "key": "X-Frame-Options", "value": "DENY" },
    { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
    { "key": "Content-Security-Policy", "value": "default-src 'self'; object-src 'none'; frame-ancestors 'none'" }
  ]}
]}}
```

Tune the CSP to the app's real sources; start in report-only mode if unsure.

## Cookies

Set `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`) on session cookies. Keep auth tokens
out of `localStorage` when a cookie will do, to shrink XSS blast radius.

## Delete doesn't delete (right to erasure)

Make the delete flow remove (or irreversibly anonymize) the user's backend records, not just the
auth entry — a Cloud Function / server job that deletes the profile, posts, and messages, plus a
check that nothing orphaned remains.

## Auth hygiene

- Enforce a real password policy (length ≥ 12 recommended, reject known-breached passwords).
- Add app-level brute-force friction (lockout/backoff/CAPTCHA) on top of the platform default.
- Keep login/reset/signup responses identical for real vs. unknown accounts (no enumeration).

## XSS / injection

Render user input as **escaped text** (framework default — don't reach for `innerHTML` /
`dangerouslySetInnerHTML`). Parameterize all DB queries. Validate/allowlist redirect targets.
