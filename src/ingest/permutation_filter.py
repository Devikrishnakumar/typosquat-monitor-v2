"""
permutation_filter.py
Generates typosquat/homoglyph permutations for a target brand using dnstwist,
PLUS combo-squat patterns (brand + common phishing keywords, e.g. flipkart-login.com),
which dnstwist does not generate on its own without an explicit wordlist.
Checks whether an incoming domain matches any of them.
"""

import argparse
import yaml
import dnstwist

# Common phishing/combo-squat keywords seen in real campaigns.
# Combined with the brand name in both orders and with common separators.
COMBO_KEYWORDS = [
    "login", "secure", "verify", "verification", "account", "update",
    "signin", "sign-in", "auth", "authentication", "confirm", "confirmation",
    "support", "help", "service", "customer", "billing", "payment",
    "wallet", "reward", "rewards", "gift", "offer", "deal", "sale",
    "app", "portal", "online", "id", "password", "reset", "unlock",
    "security", "alert", "notice", "team", "official",
]

SEPARATORS = ["-", ""]


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


def _split_domain(official_domain):
    """Returns (brand_name, tld), e.g. 'flipkart.com' -> ('flipkart', 'com')."""
    parts = official_domain.split(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return official_domain, "com"


def build_combo_squat_set(official_domain):
    """
    Generates brand+keyword and keyword+brand combinations, e.g.:
    flipkart-login.com, loginflipkart.com, secure-flipkart.com, etc.
    """
    brand, tld = _split_domain(official_domain)
    combos = set()

    for keyword in COMBO_KEYWORDS:
        for sep in SEPARATORS:
            combos.add(f"{brand}{sep}{keyword}.{tld}")
            combos.add(f"{keyword}{sep}{brand}.{tld}")

    return combos


def build_permutation_set(official_domain):
    """
    Combines dnstwist's algorithmic permutations (homoglyphs, typos,
    bitsquatting, punycode, etc.) with manually generated combo-squat
    patterns (brand + common phishing keywords), which dnstwist does not
    produce by default.
    """
    fuzzer = dnstwist.Fuzzer(official_domain)
    fuzzer.generate()

    permutations = set()
    for entry in fuzzer.permutations():
        permutations.add(entry["domain"].lower())

    permutations |= build_combo_squat_set(official_domain)

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
    print(f"Generated {len(perms)} permutations (dnstwist + combo-squat). Sample:")
    for p in list(perms)[:15]:
        print(f"  {p}")

    print("\nCombo-squat sample:")
    combo_only = build_combo_squat_set(official_domain)
    for p in list(combo_only)[:15]:
        print(f"  {p}")
