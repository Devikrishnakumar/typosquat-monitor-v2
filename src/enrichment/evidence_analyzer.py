"""
evidence_analyzer.py

Simulation-only evidence collection.

This module:
- reads a selected candidate supplied by the dashboard
- uses Playwright to capture the suspicious website
- captures the official/reference website
- finds and captures login pages
- compares login-page structure
- compares screenshots using perceptual hashing
- calculates a simulation risk score using the existing scoring model
- writes screenshots only; it does NOT write to PostgreSQL
"""

import os
import re
from urllib.parse import urljoin, urlparse

import yaml
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from src.enrichment.visual_similarity import compute_similarity
from src.scoring.risk_score import compute_risk_score, risk_level


SCREENSHOT_DIR = "data/screenshots"
BRAND_CONFIG_PATH = "config/brand_config.yaml"


def _safe_name(value):
    value = str(value or "unknown")
    return re.sub(r"[^A-Za-z0-9_-]+", "_", value)


def _load_official_domain(matched_brand=None):
    if matched_brand and "." in str(matched_brand):
        return str(matched_brand).strip()

    try:
        with open(BRAND_CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            config = yaml.safe_load(f) or {}

        return config.get("official_domain") or "paypal.com"

    except Exception:
        return "paypal.com"


def _candidate_urls(domain):
    domain = str(domain).strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        return [domain]

    return [
        f"https://{domain}",
        f"http://{domain}",
    ]


def _same_host(url_a, url_b):
    try:
        host_a = urlparse(url_a).hostname
        host_b = urlparse(url_b).hostname

        if not host_a or not host_b:
            return False

        host_a = host_a.lower()
        host_b = host_b.lower()

        return (
            host_a == host_b
            or host_a.endswith("." + host_b)
            or host_b.endswith("." + host_a)
        )

    except Exception:
        return False


def _open_site(page, domain, timeout_ms=25000):
    for url in _candidate_urls(domain):
        try:
            response = page.goto(
                url,
                timeout=timeout_ms,
                wait_until="domcontentloaded",
            )

            page.wait_for_timeout(1200)

            if response is not None and response.status >= 500:
                continue

            return {
                "success": True,
                "url": page.url,
                "title": page.title(),
                "html": page.content(),
                "status_code": response.status if response else None,
            }

        except Exception:
            continue

    return {
        "success": False,
        "url": None,
        "title": None,
        "html": None,
        "status_code": None,
    }


def _find_login_url(page, base_url):
    """
    Looks for same-site links/buttons containing login/sign-in terminology.
    No credentials are submitted and no login action is performed.
    """

    keywords = [
        "login",
        "log in",
        "sign in",
        "signin",
        "my account",
        "account login",
    ]

    ranked = []

    try:
        elements = page.locator("a, button, [role='button']")

        count = min(elements.count(), 150)

        for i in range(count):
            element = elements.nth(i)

            try:
                text = (element.inner_text(timeout=500) or "").strip().lower()
            except Exception:
                text = ""

            try:
                href = element.get_attribute("href")
            except Exception:
                href = None

            score = 0

            for keyword in keywords:
                if keyword in text:
                    score += 3

                if href and keyword.replace(" ", "") in href.lower().replace(" ", ""):
                    score += 2

            if score <= 0 or not href:
                continue

            absolute_url = urljoin(base_url, href)

            if not absolute_url.startswith(("http://", "https://")):
                continue

            if not _same_host(absolute_url, base_url):
                continue

            ranked.append((score, absolute_url))

    except Exception:
        pass

    ranked.sort(key=lambda x: x[0], reverse=True)

    return ranked[0][1] if ranked else None


def _analyze_page(html):
    if not html:
        return {
            "form_count": 0,
            "password_fields": 0,
            "email_fields": 0,
            "login_form": False,
            "submit_controls": 0,
            "button_texts": [],
            "field_types": [],
            "suspicious_phrases": [],
        }

    soup = BeautifulSoup(html, "html.parser")

    forms = soup.find_all("form")

    password_fields = soup.find_all(
        "input",
        attrs={"type": lambda value: value and value.lower() == "password"},
    )

    email_fields = soup.find_all(
        "input",
        attrs={"type": lambda value: value and value.lower() == "email"},
    )

    submit_controls = soup.find_all(
        ["button", "input"],
        attrs={
            "type": lambda value: value and value.lower() in {
                "submit",
                "button",
            }
        },
    )

    button_texts = []

    for button in soup.find_all(["button", "input"]):
        text = (
            button.get_text(" ", strip=True)
            or button.get("value")
            or ""
        ).strip()

        if text:
            button_texts.append(text[:80])

    field_types = []

    for inp in soup.find_all("input"):
        field_type = (inp.get("type") or "text").lower()

        name = (
            inp.get("name")
            or inp.get("id")
            or inp.get("placeholder")
            or ""
        ).lower()

        field_types.append({
            "type": field_type,
            "name": name[:80],
        })

    suspicious_phrases = [
        "verify your account",
        "verify your identity",
        "confirm your account",
        "update your payment",
        "unusual activity",
        "suspended account",
        "click here to verify",
        "your account has been locked",
        "login",
        "log in",
        "sign in",
        "password",
    ]

    page_text = soup.get_text(" ", strip=True).lower()

    found_phrases = [
        phrase
        for phrase in suspicious_phrases
        if phrase in page_text
    ]

    return {
        "form_count": len(forms),
        "password_fields": len(password_fields),
        "email_fields": len(email_fields),
        "login_form": bool(forms and password_fields),
        "submit_controls": len(submit_controls),
        "button_texts": button_texts[:10],
        "field_types": field_types[:20],
        "suspicious_phrases": found_phrases,
    }


def _compare_login_forms(original, candidate):
    original_fields = original.get("field_types", [])
    candidate_fields = candidate.get("field_types", [])

    original_types = [x.get("type") for x in original_fields]
    candidate_types = [x.get("type") for x in candidate_fields]

    same_field_types = original_types == candidate_types

    same_login_structure = (
        bool(original.get("login_form"))
        and bool(candidate.get("login_form"))
        and original.get("password_fields") == candidate.get("password_fields")
        and original.get("email_fields") == candidate.get("email_fields")
    )

    differences = []

    if original.get("login_form") != candidate.get("login_form"):
        differences.append("Login-form presence differs.")

    if original.get("password_fields") != candidate.get("password_fields"):
        differences.append("Password-field count differs.")

    if original.get("email_fields") != candidate.get("email_fields"):
        differences.append("Email-field count differs.")

    if original.get("submit_controls") != candidate.get("submit_controls"):
        differences.append("Submit-control count differs.")

    if not same_field_types:
        differences.append("Input-field structure differs.")

    if not differences:
        differences.append(
            "Observed login-page field structure is consistent between the two pages."
        )

    return {
        "same_field_types": same_field_types,
        "same_login_structure": same_login_structure,
        "differences": differences,
    }


def _capture_screenshot(page, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        page.screenshot(
            path=output_path,
            full_page=True,
        )
        return output_path

    except Exception:
        try:
            page.screenshot(
                path=output_path,
            )
            return output_path
        except Exception:
            return None


def _safe_similarity(candidate_path, reference_path):
    if not candidate_path or not reference_path:
        return None

    if not os.path.exists(candidate_path):
        return None

    if not os.path.exists(reference_path):
        return None

    score = compute_similarity(
        candidate_path,
        reference_path,
    )

    if score is None:
        return None

    return float(max(0.0, min(1.0, score)))


def run_simulation(candidate):
    """
    Runs the simulation for one database candidate.

    No candidate row is inserted or updated.
    """

    domain = candidate.get("domain")
    matched_brand = candidate.get("matched_brand")

    if not domain:
        raise ValueError("Selected candidate has no domain.")

    official_domain = (
        candidate.get("simulation_reference_domain")
        or _load_official_domain(matched_brand)
    )

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    safe_candidate = _safe_name(domain)
    safe_brand = _safe_name(official_domain)

    candidate_home_path = os.path.join(
        SCREENSHOT_DIR,
        f"simulation_{safe_candidate}_home.png",
    )

    candidate_login_path = os.path.join(
        SCREENSHOT_DIR,
        f"simulation_{safe_candidate}_login.png",
    )

    reference_home_path = os.path.join(
        SCREENSHOT_DIR,
        f"simulation_reference_{safe_brand}_home.png",
    )

    reference_login_path = os.path.join(
        SCREENSHOT_DIR,
        f"simulation_reference_{safe_brand}_login.png",
    )

    result = {
        "simulation": True,
        "domain": domain,
        "matched_brand": matched_brand,
        "official_domain": official_domain,
        "candidate_home_screenshot": None,
        "candidate_login_screenshot": None,
        "reference_home_screenshot": None,
        "reference_login_screenshot": None,
        "candidate_page": {},
        "reference_page": {},
        "candidate_login": {},
        "reference_login": {},
        "login_comparison": {},
        "visual_similarity": None,
        "login_similarity": None,
        "risk_score": 0,
        "risk_level": "LOW",
        "production_risk_score": candidate.get("risk_score"),
        "production_risk_level": candidate.get("risk_level"),
        "status": "started",
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
        )

        context = browser.new_context(
            viewport={
                "width": 1280,
                "height": 900,
            }
        )

        candidate_page = context.new_page()

        candidate_page_info = _open_site(
            candidate_page,
            domain,
        )

        result["candidate_page"] = candidate_page_info

        if candidate_page_info["success"]:
            result["candidate_home_screenshot"] = _capture_screenshot(
                candidate_page,
                candidate_home_path,
            )

            candidate_login_url = _find_login_url(
                candidate_page,
                candidate_page_info["url"],
            )

            if candidate_login_url:
                try:
                    candidate_page.goto(
                        candidate_login_url,
                        timeout=25000,
                        wait_until="domcontentloaded",
                    )
                    candidate_page.wait_for_timeout(1200)

                    result["candidate_login_screenshot"] = _capture_screenshot(
                        candidate_page,
                        candidate_login_path,
                    )

                    candidate_login_html = candidate_page.content()

                except Exception:
                    candidate_login_html = candidate_page_info["html"]

            else:
                candidate_login_html = candidate_page_info["html"]

            result["candidate_login"] = _analyze_page(
                candidate_login_html
            )

        reference_page = context.new_page()

        reference_page_info = _open_site(
            reference_page,
            official_domain,
        )

        result["reference_page"] = reference_page_info

        if reference_page_info["success"]:
            result["reference_home_screenshot"] = _capture_screenshot(
                reference_page,
                reference_home_path,
            )

            reference_login_url = _find_login_url(
                reference_page,
                reference_page_info["url"],
            )

            if reference_login_url:
                try:
                    reference_page.goto(
                        reference_login_url,
                        timeout=25000,
                        wait_until="domcontentloaded",
                    )
                    reference_page.wait_for_timeout(1200)

                    result["reference_login_screenshot"] = _capture_screenshot(
                        reference_page,
                        reference_login_path,
                    )

                    reference_login_html = reference_page.content()

                except Exception:
                    reference_login_html = reference_page_info["html"]

            else:
                reference_login_html = reference_page_info["html"]

            result["reference_login"] = _analyze_page(
                reference_login_html
            )

        browser.close()

    result["visual_similarity"] = _safe_similarity(
        result["candidate_home_screenshot"],
        result["reference_home_screenshot"],
    )

    result["login_similarity"] = _safe_similarity(
        result["candidate_login_screenshot"],
        result["reference_login_screenshot"],
    )

    result["login_comparison"] = _compare_login_forms(
        result["reference_login"],
        result["candidate_login"],
    )

    candidate_live = bool(
        result["candidate_page"].get("success")
    )

    suspicious_phrase_count = len(
        result["candidate_login"].get("suspicious_phrases", [])
    )

    score, _breakdown = compute_risk_score(
        is_live=candidate_live,
        visual_similarity=result["visual_similarity"],
        has_login_form=result["candidate_login"].get("login_form", False),
        suspicious_phrase_count=suspicious_phrase_count,
    )

    result["risk_score"] = score
    result["risk_level"] = risk_level(score)

    result["risk_breakdown"] = _breakdown

    result["status"] = "completed"

    return result
