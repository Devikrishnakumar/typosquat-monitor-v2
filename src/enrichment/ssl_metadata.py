"""
ssl_metadata.py
Connects to a domain over TLS and inspects certificate metadata:
issuer, validity window, SAN count. Free/short-lived certs with few
SANs are a common phishing-infrastructure pattern.

Uses getpeercert(binary_form=True) + cryptography, because Python's
ssl module returns an EMPTY dict from getpeercert() when verify_mode
is CERT_NONE -- and we deliberately disable verification since we're
inspecting potentially self-signed / broken certs on suspicious domains.
"""

import ssl
import socket
from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import NameOID


def get_ssl_metadata(domain, port=443, timeout=5):
    """
    Returns a dict of certificate metadata, or None if the connection/handshake fails.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect the cert even if untrusted/self-signed

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
    except Exception:
        return None

    if not der_cert:
        return None

    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception:
        return None

    try:
        issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer = issuer_attrs[0].value if issuer_attrs else cert.issuer.rfc4514_string()
    except Exception:
        issuer = cert.issuer.rfc4514_string()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_count = len(san_ext.value)
    except x509.ExtensionNotFound:
        san_count = 0

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    validity_days = (not_after - not_before).days

    free_ca_markers = ("let's encrypt", "zerossl", "cpanel", "r3", "e1", "e5", "e6")
    is_free_ca = any(marker in issuer.lower() for marker in free_ca_markers)

    return {
        "issuer": issuer,
        "san_count": san_count,
        "validity_days": validity_days,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_free_or_short_lived": bool(is_free_ca or validity_days <= 100),
    }


if __name__ == "__main__":
    for d in ["google.com", "github.com"]:
        print(d, "->", get_ssl_metadata(d))
