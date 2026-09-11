"""
Quick sanity test: confirms is_suspicious() correctly flags a known
typosquat domain, without needing to wait for live CT stream traffic.
"""

from permutation_filter import get_brand_settings, build_permutation_set, is_suspicious

official_domain = get_brand_settings(cli_brand="flipkart.com")
permutation_set = build_permutation_set(official_domain)

test_cases = [
    "flipkaret.com",
    "fli8pkart.com",
    "google.com",
    "flipkart.com",
]

for domain in test_cases:
    result = is_suspicious(domain, permutation_set, official_domain=official_domain)
    status = "MATCH" if result else "no match"
    print(f"{domain:30s} -> {status}")
