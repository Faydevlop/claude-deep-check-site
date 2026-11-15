#!/usr/bin/env python3
"""Scan a JS bundle (URL or local file) for leaked secrets and client-side auth logic.

Usage:
    python scan_bundle.py https://example.com/assets/index-abcd1234.js
    python scan_bundle.py ./index.js

Every hit is a LEAD to verify by hand, not a confirmed finding. False positives are expected.
Standard library only — no dependencies.
"""
import sys
import re
import urllib.request
import ssl

# (label, regex, why it matters). Patterns are deliberately broad; verify each hit in context.
PATTERNS = [
    ("Google/Firebase API key", r"AIza[0-9A-Za-z_\-]{35}",
     "Firebase web key (public by design) — pivot to checking Firestore/Storage rules."),
    ("Firebase projectId", r"projectId\s*[:=]\s*[\"']([a-z0-9\-]+)[\"']",
     "The project id you need for Firestore requests."),
    ("Supabase anon/JWT key", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "A JWT (likely Supabase anon key or a token) — decode it; check RLS."),
    ("AWS access key id", r"A(?:KIA|SIA|GPA|IDA|ROA)[0-9A-Z]{16}",
     "AWS key id — if a secret key is nearby this is serious."),
    ("Stripe key", r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}",
     "Stripe key — a live SECRET (sk_live) in client code is critical."),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token in client code."),
    ("SendGrid key", r"SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}", "SendGrid API key."),
    ("OpenAI key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI API key in client code."),
    ("Google OAuth client secret", r"GOCSPX-[0-9A-Za-z_\-]{20,}", "OAuth client secret."),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
     "Private key material shipped to the browser."),
    ("JWT signing / generic secret", r"(?i)(?:secret|signing[_-]?key|private[_-]?key)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
     "A named secret assigned a literal value in client code."),
    ("Hardcoded salt / IV", r"(?i)(?:salt|iv|nonce)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
     "A static/shared salt or IV defeats per-user crypto."),
    ("Client-side admin check", r"(?i)is_?admin\s*[:=]",
     "Admin status decided in the browser — the server likely doesn't enforce it."),
    ("Admin email allowlist", r"(?i)\[\s*[\"'][a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}[\"']\s*\]",
     "A hardcoded email allowlist — leaks a staff identity; no real role system."),
    ("Client-side role/tier logic", r"(?i)(?:role|accountType|plan|tier)\s*===?\s*[\"'][^\"']+[\"']",
     "Role/paid-tier decided client-side — test whether the backend enforces it."),
    ("Bare email address", r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}",
     "Any email literal — may be a leaked admin/staff address."),
]


def load(src):
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "deep-check-site/1.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return r.read().decode("utf-8", "replace")
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def snippet(text, start, end, pad=40):
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    return text[a:b].replace("\n", " ")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    text = load(sys.argv[1])
    print(f"Scanned {len(text):,} chars from {sys.argv[1]}\n")

    total = 0
    for label, pattern, why in PATTERNS:
        seen = set()
        hits = []
        for m in re.finditer(pattern, text):
            key = m.group(0)
            if key in seen:
                continue
            seen.add(key)
            hits.append((m.group(0), snippet(text, m.start(), m.end())))
            if len(hits) >= 5:  # cap noisy patterns (e.g. bare emails)
                break
        if hits:
            total += len(hits)
            print(f"[{label}]  — {why}")
            for value, ctx in hits:
                shown = value if len(value) <= 60 else value[:57] + "..."
                print(f"    match: {shown}")
                print(f"    near : ...{ctx.strip()}...")
            print()

    if total == 0:
        print("No matches. That is not proof the bundle is clean — review it by hand too.")
    else:
        print(f"{total} lead(s). Verify each in context before reporting as a finding.")


if __name__ == "__main__":
    main()
