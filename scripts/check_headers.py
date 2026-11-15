#!/usr/bin/env python3
"""Check a URL for standard HTTP security headers, cookie flags, and HTTPS behavior.

Usage:
    python check_headers.py https://example.com

Read-only: issues a single GET (following redirects) and reports what it sees.
Standard library only — no dependencies.
"""
import sys
import urllib.request
import urllib.error
import ssl
from http.cookies import SimpleCookie

SECURITY_HEADERS = {
    "content-security-policy": "Controls what resources load; core XSS / injection defense.",
    "strict-transport-security": "Forces HTTPS on repeat visits (HSTS).",
    "x-frame-options": "Anti-clickjacking (or use CSP frame-ancestors).",
    "x-content-type-options": "Stops MIME-type sniffing (should be 'nosniff').",
    "referrer-policy": "Limits referrer leakage to other sites.",
    "permissions-policy": "Restricts powerful browser features (camera, geolocation, ...).",
}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "deep-check-site/1.0"})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=20, context=ctx)
        return resp.geturl(), resp.status, resp.headers
    except urllib.error.HTTPError as e:
        # An error response still carries headers worth inspecting.
        return url, e.code, e.headers


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    final_url, status, headers = fetch(url)
    lower = {k.lower(): v for k, v in headers.items()}

    print(f"Target        : {url}")
    print(f"Final URL     : {final_url}  (status {status})")
    print(f"Server        : {lower.get('server', '(not disclosed)')}")
    upgraded = final_url.startswith("https://")
    print(f"HTTPS         : {'yes' if upgraded else 'NO — served over plain HTTP'}")
    print()

    print("Security headers")
    print("-" * 60)
    missing = []
    for name, why in SECURITY_HEADERS.items():
        if name in lower:
            print(f"  [present] {name}: {lower[name][:80]}")
        else:
            print(f"  [ABSENT ] {name}  <- {why}")
            missing.append(name)
    print()

    # Cookie flags
    raw_cookies = headers.get_all("set-cookie") or []
    if raw_cookies:
        print("Cookies")
        print("-" * 60)
        for raw in raw_cookies:
            c = SimpleCookie()
            c.load(raw)
            for key, morsel in c.items():
                flags = []
                if not morsel["secure"]:
                    flags.append("missing Secure")
                if not morsel["httponly"]:
                    flags.append("missing HttpOnly")
                if not morsel["samesite"]:
                    flags.append("missing SameSite")
                note = ", ".join(flags) if flags else "Secure + HttpOnly + SameSite ok"
                print(f"  {key}: {note}")
        print()

    if missing:
        print(f"Summary: {len(missing)} of {len(SECURITY_HEADERS)} security headers absent.")
    else:
        print("Summary: all checked security headers present.")


if __name__ == "__main__":
    main()
