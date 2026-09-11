"""
content_signals.py
Analyzes a page's HTML content for phishing indicators:
login forms, password fields, and suspicious verification language.
"""

from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

SUSPICIOUS_PHRASES = [
    "verify your account",
    "verify your identity",
    "confirm your account",
    "update your payment",
    "unusual activity",
    "suspended account",
    "click here to verify",
    "your account has been locked",
]


def fetch_page_html(domain, timeout_ms=20000):
    """Fetches rendered HTML for a domain, trying HTTPS then HTTP."""
    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        for url in urls_to_try:
            try:
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
                html = page.content()
                browser.close()
                return html
            except Exception:
                continue

        browser.close()
        return None


def analyze_content(html):
    """
    Returns a dict with:
      - has_login_form: bool
      - has_password_field: bool
      - suspicious_phrases_found: list of matched phrases
    """
    if not html:
        return {
            "has_login_form": False,
            "has_password_field": False,
            "suspicious_phrases_found": [],
        }

    soup = BeautifulSoup(html, "html.parser")

    password_fields = soup.find_all("input", {"type": "password"})
    has_password_field = len(password_fields) > 0

    forms = soup.find_all("form")
    has_login_form = has_password_field and len(forms) > 0

    page_text = soup.get_text().lower()
    found_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in page_text]

    return {
        "has_login_form": has_login_form,
        "has_password_field": has_password_field,
        "suspicious_phrases_found": found_phrases,
    }


if __name__ == "__main__":
    test_domains = ["github.com", "example.com"]

    for domain in test_domains:
        print(f"\nAnalyzing {domain}...")
        html = fetch_page_html(domain)
        result = analyze_content(html)
        print(f"  has_login_form: {result['has_login_form']}")
        print(f"  has_password_field: {result['has_password_field']}")
        print(f"  suspicious_phrases_found: {result['suspicious_phrases_found']}")
