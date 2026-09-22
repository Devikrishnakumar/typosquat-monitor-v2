"""
mx_check.py
Checks whether a domain has active mail infrastructure (MX records),
which signals capability for spear-phishing / email-based attacks.
"""

import dns.resolver


def has_mx_records(domain, timeout=5):
    """Returns True if the domain has one or more MX records configured."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return len(answers) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception:
        return False


if __name__ == "__main__":
    for d in ["google.com", "this-domain-should-not-exist-12345.com"]:
        print(d, "-> MX:", has_mx_records(d))
