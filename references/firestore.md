# Firestore request shapes (authorized testing)

All of these need `PROJECT` (the `projectId` from `firebaseConfig`) and a bearer token from an
**authorized, signed-in** session. Grab the token in the browser console of the logged-in app:

```js
// Finds the Firebase auth entry in localStorage and pulls the current access token.
const authObj = JSON.parse(
  localStorage.getItem(Object.keys(localStorage).find(k => k.includes('authUser')))
);
const token = authObj.stsTokenManager.accessToken;
const uid   = authObj.uid;
```

Base URL: `https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents`

## 1. Can a normal user list a whole collection? (broad-read / rule too open)

```js
fetch(`${BASE}/users?pageSize=5`, { headers: { Authorization: `Bearer ${token}` } })
  .then(r => r.json())
  .then(j => console.log(j.documents?.length, 'docs', j));
```

If this returns documents belonging to **other** users, the read rule isn't scoped to the
owner. Report the count and 1–2 **redacted** sample fields as evidence. Repeat for sensitive
collections: `reports`, `messages`, `orders`, `payments`, `admin*`.

## 2. What sensitive fields are inside those records?

Inspect returned documents for: `email`, `phone`, `address`, private key material
(`e2ePrivateKey`, `privateKey`), tokens, internal flags (`role`, `accountType`, `isAdmin`).
A readable collection is worse when the records carry secrets.

## 3. Privilege / tier self-escalation (write test — throwaway account, then revert)

```js
// Attempt to set a privileged field on YOUR OWN document.
fetch(`${BASE}/users/${uid}?updateMask.fieldPaths=accountType`, {
  method: 'PATCH',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ fields: { accountType: { stringValue: 'business' } } })
}).then(r => r.json()).then(j => console.log('now:', j.fields?.accountType?.stringValue));
```

If accepted, the write rule doesn't restrict *which* fields a user may self-edit. **Revert
immediately** by PATCHing the field back to its original value. Only do this on a throwaway
account, never a real user.

## 4. Cross-user write (should FAIL — confirms a negative)

Try PATCHing a document whose id is **not** your uid. A correct `403 PERMISSION_DENIED`
confirms writes are scoped even if reads aren't — report it under "working as intended".

## 5. Did account deletion really delete? (right-to-erasure)

After deleting a throwaway account through the app's own flow, query for it directly:

```js
fetch(`${BASE}:runQuery`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ structuredQuery: {
    from: [{ collectionId: 'users' }],
    where: { fieldFilter: { field: { fieldPath: 'email' }, op: 'EQUAL',
             value: { stringValue: 'throwaway+demo@example.com' } } },
    limit: 1 } })
}).then(r => r.json()).then(j => console.log(j[0]?.document ? 'STILL PRESENT' : 'gone'));
```

## Storage rules (confirm a negative)

Try listing/reading a Storage path without the exact object URL. A blocked anonymous/broad
listing is good — report it under "working as intended".

> Reminder: keep reads minimal (pageSize 3–5), redact other people's data in the report, and
> never run high-volume loops.
