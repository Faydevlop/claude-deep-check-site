# Generic authorization playbook (any backend)

The managed-backend checks in `firestore.md` are special cases of three universal flaws. For
a custom REST/GraphQL API, Supabase, Appwrite, etc., test these directly.

## IDOR — Insecure Direct Object Reference (broken object-level read/write)

The server trusts an ID in the request without checking you own it.

1. Capture an authenticated request that fetches *your* object
   (`GET /api/users/123`, `GET /api/orders/abc`, a GraphQL `node(id:)`).
2. Change the ID to one you don't own (decrement/increment, a known other id, a guessed UUID).
3. If you get back someone else's object → **broken object-level authorization (IDOR)**,
   usually High/Critical depending on the data.
4. Repeat for **write/delete** verbs (`PUT`, `PATCH`, `DELETE`) — being able to *modify*
   another object is worse than reading it.

Watch for IDs in: path segments, query params, JSON body, GraphQL variables, and hidden form
fields.

## Broken function-level authorization (missing role check)

Admin/privileged endpoints that only the UI hides, not the server.

1. From the bundle, find endpoints the client calls only for admins/privileged users
   (`/api/admin/*`, `/api/users/:id/ban`, `exportAll`, feature-flagged mutations).
2. Call them directly with a **normal** user's token.
3. If they execute → the server relies on the client to hide them. Finding.

## Mass assignment / privileged self-write

The server accepts fields from the client it should set itself.

1. Find an endpoint that updates your own object (profile update, settings).
2. Add privileged fields to the body the UI never sends: `role`, `isAdmin`, `accountType`,
   `plan`, `isVerified`, `credits`, `emailVerified`.
3. If the server persists them → mass-assignment escalation. Test on a throwaway account and
   revert.

## Turning a lead into a finding

- **Reproduce it twice** before reporting — once can be a caching/race fluke.
- Capture the **exact request and response** (method, URL, the changed field, status code).
- **Redact** other users' personal data to a count + 1–2 masked samples.
- State impact concretely: "any signed-in user can read every member's email and phone",
  not "possible data exposure".
- Record and **revert** every write; note any residue (e.g. an orphaned record you couldn't
  delete) with its exact path.
