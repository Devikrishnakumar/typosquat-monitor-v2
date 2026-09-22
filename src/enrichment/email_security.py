"""
email_security.py
Checks SPF (TXT record on the domain) and DMARC (TXT record on _dmarc.<domain>).
Presence/absence of these is a secondary phishing-infrastructure signal.
"""

import dns.resolver


def _txt_records(name, timeout=5):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def check_spf(domain):
    """Returns True if an SPF record (v=spf1 ...) is published for the domain."""
    for txt in _txt_records(domain):
        if txt.lower().startswith("v=spf1"):
            return True
    return False


def check_dmarc(domain):
    """Returns True if a DMARC record is published at _dmarc.<domain>."""
    for txt in _txt_records(f"_dmarc.{domain}"):
        if txt.lower().startswith("v=dmarc1"):
            return True
    return False


def check_email_security(domain):
    return {"has_spf": check_spf(domain), "has_dmarc": check_dmarc(domain)}


if __name__ == "__main__":
    for d in ["google.com", "this-domain-should-not-exist-12345.com"]:
        print(d, "->", check_email_security(d))
