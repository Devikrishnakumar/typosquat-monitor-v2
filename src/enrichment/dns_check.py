"""
dns_check.py
Checks whether a domain is actually live (resolves to an IP address).
Uses the OS-level resolver via socket, which works reliably even on
networks that block raw DNS queries to external resolvers.
"""

import socket


def is_domain_live(domain, timeout=3):
    """
    Returns True if the domain resolves to an IP address.
    Returns False if it doesn't resolve (NXDOMAIN-equivalent, timeout, etc).
    """
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False  # domain doesn't resolve
    except socket.timeout:
        return False
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)


if __name__ == "__main__":
    test_domains = [
        "google.com",
        "flipkart.com",
        "this-domain-should-not-exist-xyz123.com",
    ]

    for domain in test_domains:
        result = is_domain_live(domain)
        status = "LIVE" if result else "not live"
        print(f"{domain:45s} -> {status}")
