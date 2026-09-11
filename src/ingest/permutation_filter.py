"""
permutation_filter.py
Generates typosquat/homoglyph permutations for a target brand using dnstwist,
and checks whether an incoming domain matches any of them.
"""

import argparse
import yaml
import dnstwist


def load_brand_config(config_path="config/brand_config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_brand_settings(cli_brand=None, config_path="config/brand_config.yaml"):
    config = load_brand_config(config_path)

    if cli_brand:
        official_domain = cli_brand
    else:
        official_domain = config["official_domain"]

    return official_domain


def build_permutation_set(official_domain):
    fuzzer = dnstwist.Fuzzer(official_domain)
    fuzzer.generate()

    permutations = set()
    for entry in fuzzer.permutations():
        permutations.add(entry["domain"].lower())

    return permutations


def is_suspicious(domain, permutation_set, official_domain=None):
    domain = domain.lower().lstrip("*.")
    if official_domain and domain == official_domain.lower():
        return False  # never flag the brand's own real domain
    return domain in permutation_set


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    args = parser.parse_args()

    official_domain = get_brand_settings(cli_brand=args.brand)
    perms = build_permutation_set(official_domain)

    print(f"Brand: {official_domain}")
    print(f"Generated {len(perms)} permutations. Sample:")
    for p in list(perms)[:15]:
        print(f"  {p}")
