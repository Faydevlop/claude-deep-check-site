# Demo guide format (showing a non-technical owner, live)

When the user wants to *show* an owner the issues in their own browser, produce a companion
"demo guide" alongside the findings report. It turns each finding into a short, safe,
repeatable live demonstration using only Chrome DevTools — nothing to install.

## Rules for a good demo guide

- **Each demo is self-contained.** Every console snippet fetches its own fresh auth token so
  demos can run in any order, standalone. Don't make demo 4 depend on demo 1.
- **Label the risk** on every demo: *read-only (safe anytime)* vs.
  *⚠️ changes real data — undo immediately* (and include the undo snippet right after).
- **Plain-English "what to say"** line per demo — the sentence to speak while it runs, framed
  by impact, not jargon.
- **Lead with the most convincing read-only demo** (usually "I can read every member's private
  data"), and put any data-changing demo last with a bold undo step.
- Include a short **"if you see 401 Unauthorized"** note: reload the site, confirm still
  logged in, re-paste the whole snippet.
- End with a **quick-reference table**: `# | Demo | What it proves`.

## Per-demo template

```
## Demo N — "<plain-English claim>" (read-only | ⚠️ changes data — undo right after)

Setup: <logged in normally? incognito? which DevTools tab>

Steps:
1. <paste this snippet / do this>
2. <what to point at in the output>

```js
// self-contained snippet that grabs its own token and proves the one point
```

What to say: "<one or two spoken sentences, framed by impact>"
```

## Safety

- Only read-only demos by default. A data-changing demo (e.g. self-upgrading account type)
  must use a throwaway account and carry its undo snippet inline.
- Never put another real user's unredacted data on screen in a shared/recorded demo — use
  `pageSize` 3–5 and remind the presenter the output contains real PII.
