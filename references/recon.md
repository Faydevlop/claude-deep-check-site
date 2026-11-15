# Backend fingerprints — where each stack leaks

Identify the backend first; it tells you which checks matter. Look in the HTML, the loaded JS
bundles, and the Network tab for these signals.

## Firebase / Firestore

**Fingerprint:** a `firebaseConfig` object in a bundle, requests to
`firestore.googleapis.com`, `identitytoolkit.googleapis.com`, domains ending in
`firebaseapp.com` / `web.app`, an `apiKey` starting `AIza...`.

```js
const firebaseConfig = {
  apiKey: "AIza....",
  authDomain: "PROJECT.firebaseapp.com",
  projectId: "PROJECT",            // <-- you need this id for every Firestore request
  ...
};
```

- The web API key is **not** a secret — Google ships it to every client by design. Do not
  report it as a finding on its own.
- The real control surface is **Firestore Security Rules** + **Storage Rules**, enforced
  server-side. You can't read the rules directly, so you infer them by what requests succeed.
- See `firestore.md` for request shapes.

## Supabase

**Fingerprint:** `*.supabase.co`, a long `anon` key that is a JWT (decode it — `role: "anon"`),
requests to `/rest/v1/<table>` and `/auth/v1`.

- Like Firebase, the anon key is public by design. The control surface is **Row Level
  Security (RLS)** policies.
- Test: `GET https://PROJECT.supabase.co/rest/v1/<table>?select=*` with
  `apikey: <anon>` and `Authorization: Bearer <session jwt>`. If RLS is off or too loose,
  you get rows you shouldn't.

## Other backends

- **AWS Amplify / Cognito**: `cognito-idp.*.amazonaws.com`, `aws-exports.js`, identity pool
  IDs. Check for overly broad IAM on unauthenticated identities.
- **Appwrite**: `/v1/` endpoints, a project id header `X-Appwrite-Project`. Collection
  permissions are the control surface.
- **Pocketbase**: `/api/collections/<name>/records`. Check collection API rules.
- **Custom REST / GraphQL**: no managed rules — authorization is hand-written per endpoint,
  so IDOR and missing object-level checks are common. Enumerate endpoints from the bundle and
  the Network tab, then run the `authz.md` playbook.

## Enumerating the JS bundles

- Open the Network tab, filter to JS, reload, and list every script. The largest
  `index-*.js` / `main-*.js` / `vendor-*.js` is usually where config and logic live.
- Bundle filenames are content-hashed and change on each deploy — never hardcode a hash; find
  the current largest JS file each time.
- Save the bundle URL(s) and feed them to `scripts/scan_bundle.py`.
