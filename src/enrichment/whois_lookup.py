"""
whois_lookup.py
Fetches domain registration info via RDAP (the modern HTTPS-based
replacement for WHOIS), used to populate abuse contact info in the
takedown report. Uses HTTPS instead of raw WHOIS port 43, which many
networks block.
"""

import requests


def get_whois_info(domain, timeout=20):
    """
    Returns a dict with registrar, creation_date, and abuse contact info.
    Returns a dict with all None/empty values if lookup fails.
    """
    url = f"https://rdap.org/domain/{domain}"

    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (compatible; TyposquatMonitor/1.0)"})
        if response.status_code != 200:
            return _empty_result()

        data = response.json()

        registrar = None
        abuse_emails = []

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])

            if "registrar" in roles:
                for item in vcard[1] if len(vcard) > 1 else []:
                    if item[0] == "fn":
                        registrar = item[3]

            if "abuse" in roles:
                for item in vcard[1] if len(vcard) > 1 else []:
                    if item[0] == "email":
                        abuse_emails.append(item[3])

        creation_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")

        name_servers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

        return {
            "registrar": registrar,
            "creation_date": creation_date,
            "emails": abuse_emails,
            "name_servers": name_servers,
        }

    except Exception as e:
        print(f"RDAP lookup failed for {domain}: {e}")
        return _empty_result()


def _empty_result():
    return {"registrar": None, "creation_date": None, "emails": [], "name_servers": []}


if __name__ == "__main__":
    result = get_whois_info("google.com")
    for key, value in result.items():
        print(f"{key}: {value}")
