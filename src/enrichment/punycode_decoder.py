"""
punycode_decoder.py
Decodes Punycode/IDN domains (xn--...) into their real Unicode form,
so homoglyph tricks (lookalike characters) are visible instead of hidden.
"""

import idna


def decode_domain(domain):
    """
    Returns (decoded_domain, is_punycode) tuple.
    If the domain isn't Punycode-encoded, returns the original domain unchanged.
    """
    try:
        if "xn--" in domain.lower():
            decoded = idna.decode(domain)
            return decoded, True
        else:
            return domain, False
    except Exception:
        return domain, False


if __name__ == "__main__":
    test_domains = [
        "xn--pypal-4ve.com",       # fake test punycode-style example
        "flipkart.com",            # plain ASCII, not punycode
        "xn--flkart-x8a28i.com",   # a real one we saw earlier from dnstwist
    ]

    for domain in test_domains:
        decoded, is_puny = decode_domain(domain)
        marker = "[PUNYCODE]" if is_puny else "[plain]"
        print(f"{marker:12s} {domain:30s} -> {decoded}")
