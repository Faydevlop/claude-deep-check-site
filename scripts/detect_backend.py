#!/usr/bin/env python3
"""Intelligently classify a site's backend from its HTML + JS bundles.

Usage:
    python detect_backend.py https://example.com

Fetches the page, discovers the script bundles it loads, downloads them, and scores a set of
backend fingerprints by the signals it actually finds. Prints a ranked verdict with the
evidence behind it and which follow-up checks matter for the winner.

Read-only. Standard library only — no dependencies. Every verdict is a hypothesis to confirm
by hand; a thin/minified bundle can hide or fake signals.
"""
import sys
import re
import ssl
import urllib.request
from urllib.parse import urljoin

UA = {"User-Agent": "deep-check-site/1.0"}

# backend -> list of (weight, compiled regex, human label). Higher weight = stronger signal.
SIGNALS = {
    "Firebase / Firestore (managed)": [
        (5, r"firestore\.googleapis\.com", "talks to Firestore REST API"),
        (4, r"identitytoolkit\.googleapis\.com", "Firebase Auth endpoint"),
        (4, r"firebaseConfig|initializeApp\(", "Firebase SDK init"),
        (3, r"\.firebaseapp\.com|\.web\.app", "Firebase hosting domain"),
        (3, r"projectId\s*[:=]\s*[\"'][a-z0-9\-]+[\"']", "firebaseConfig projectId"),
        (2, r"AIza[0-9A-Za-z_\-]{35}", "Google/Firebase API key"),
    ],
    "Supabase (managed Postgres + RLS)": [
        (5, r"[a-z0-9]+\.supabase\.co", "Supabase project domain"),
        (4, r"supabase\.co/(?:rest|auth|storage)/v1", "Supabase REST/Auth/Storage API"),
        (4, r"createClient\([^)]*supabase", "supabase-js client init"),
        (3, r"\"?apikey\"?\s*[:=]", "anon apikey header usage"),
    ],
    "AWS Amplify / Cognito (managed)": [
        (5, r"cognito-idp\.[a-z0-9\-]+\.amazonaws\.com", "Cognito identity provider"),
        (4, r"aws-exports|awsmobile", "Amplify config object"),
        (3, r"execute-api\.[a-z0-9\-]+\.amazonaws\.com", "API Gateway endpoint"),
        (3, r"appsync-api\.[a-z0-9\-]+\.amazonaws\.com", "AppSync (GraphQL) endpoint"),
    ],
    "Appwrite (self/managed BaaS)": [
        (5, r"/v1/(?:account|databases|storage)\b", "Appwrite REST paths"),
        (4, r"X-Appwrite-Project|appwrite", "Appwrite project header/SDK"),
    ],
    "Pocketbase (self-hosted BaaS)": [
        (5, r"/api/collections/[a-z0-9_]+/records", "Pocketbase records API"),
        (3, r"pocketbase", "Pocketbase SDK reference"),
    ],
    "Custom GraphQL API": [
        (4, r"/graphql\b", "GraphQL endpoint"),
        (3, r"__typename|ApolloClient|urql", "GraphQL client library"),
    ],
    "Custom REST API (hand-rolled authz)": [
        (3, r"/api/v[0-9]+/|/api/[a-z]+", "versioned/custom REST paths"),
        (2, r"Authorization:\s*Bearer|localStorage\.(get|set)Item\([\"'](?:token|jwt|access)", "custom bearer-token handling"),
    ],
    "Static / no obvious backend": [
        (2, r"netlify|vercel\.app|github\.io|cloudfront\.net", "static host / CDN only"),
    ],
}

FOLLOWUP = {
    "Firebase / Firestore (managed)":
        "Key is public by design — the real surface is Firestore & Storage *security rules*. "
        "Test collection reads and privileged self-writes (see references/firestore.md).",
    "Supabase (managed Postgres + RLS)":
        "Anon key is public by design — the surface is *Row Level Security*. Try "
        "GET /rest/v1/<table>?select=* with the anon key + session JWT and see what rows return.",
    "AWS Amplify / Cognito (managed)":
        "Check the unauthenticated identity pool's IAM scope and per-resolver/field authz on "
        "AppSync; look for over-broad guest permissions.",
    "Appwrite (self/managed BaaS)":
        "Collection & document *permissions* are the control surface — test read/write as a "
        "normal user across collections.",
    "Pocketbase (self-hosted BaaS)":
        "Each collection's API *rules* are the control surface — test list/view/update rules.",
    "Custom GraphQL API":
        "Enumerate queries/mutations (often introspectable); test object-level & field-level "
        "authz and mass assignment (references/authz.md).",
    "Custom REST API (hand-rolled authz)":
        "Authorization is hand-written per endpoint — IDOR and missing function-level checks "
        "are the usual wins (references/authz.md).",
    "Static / no obvious backend":
        "May be fully static, or the backend is behind a path/API you haven't seen yet. "
        "Watch the Network tab while using the app before concluding there's no backend.",
}

SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)


def fetch(url, as_bytes=False):
    req = urllib.request.Request(url, headers=UA)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        data = r.read()
    return data if as_bytes else data.decode("utf-8", "replace")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        html = fetch(url)
    except Exception as e:
        print(f"Could not fetch {url}: {e}")
        sys.exit(2)

    # Gather the page plus its same-origin JS bundles (cap to keep it light).
    corpus = html
    srcs = [urljoin(url, s) for s in SCRIPT_SRC.findall(html)]
    js_srcs = [s for s in srcs if ".js" in s.lower()][:6]
    fetched = []
    for s in js_srcs:
        try:
            corpus += "\n" + fetch(s)
            fetched.append(s)
        except Exception:
            pass

    print(f"Target : {url}")
    print(f"Bundles inspected : {len(fetched)}")
    for s in fetched:
        print(f"   - {s}")
    print()

    scored = []
    for backend, sigs in SIGNALS.items():
        hits, score = [], 0
        for weight, pattern, label in sigs:
            if re.search(pattern, corpus, re.I):
                score += weight
                hits.append(label)
        if score:
            scored.append((score, backend, hits))
    scored.sort(reverse=True)

    if not scored:
        print("Verdict: inconclusive — no known backend fingerprints matched.")
        print("The app may load data lazily; watch the Network tab while using it.")
        return

    top = scored[0][0]
    print("Backend verdict (ranked by matched signal strength)")
    print("=" * 62)
    for score, backend, hits in scored:
        conf = "high" if score >= 7 else "medium" if score >= 4 else "low"
        lead = ">>" if score == top else "  "
        print(f"{lead} {backend}  —  score {score} ({conf} confidence)")
        for h in hits:
            print(f"      + {h}")
    print()

    best = scored[0][1]
    print(f"Most likely: {best}")
    print(f"Next checks: {FOLLOWUP[best]}")
    if len(scored) > 1 and scored[1][0] >= top - 1:
        print(f"(Close runner-up: {scored[1][1]} — the app may use more than one backend.)")


if __name__ == "__main__":
    main()
