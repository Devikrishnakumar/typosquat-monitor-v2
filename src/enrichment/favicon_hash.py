"""
favicon_hash.py
Fetches /favicon.ico and computes its MMH3 hash, the same technique
Shodan/Censys use to fingerprint known phishing kits and brand impersonation pages.
"""

import mmh3
import requests
import base64


def get_favicon_hash(domain, timeout=6):
    """
    Returns the MMH3 hash of the favicon as an int, or None if unreachable.
    Uses the same base64-then-hash approach as Shodan's http.favicon.hash.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/favicon.ico"
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            if resp.status_code == 200 and resp.content:
                encoded = base64.encodebytes(resp.content)
                return mmh3.hash(encoded)
        except requests.RequestException:
            continue
    return None


if __name__ == "__main__":
    for d in ["github.com", "google.com"]:
        print(d, "-> favicon hash:", get_favicon_hash(d))
