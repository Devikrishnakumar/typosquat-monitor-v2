"""
report_generator.py
Generates a PDF takedown/abuse report for a detected candidate,
combining detection data, evidence, side-by-side visual comparison,
and WHOIS/registrar info.
"""

import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa

TEMPLATE_DIR = "src/reporting/templates"
REPORT_OUTPUT_DIR = "reports"
REFERENCE_SCREENSHOT_PATH = "reference_assets/brand_reference_screenshot.png"


def generate_report(candidate, whois_info=None):
    """
    candidate: dict with keys matching the candidates table row.
    whois_info: dict from get_whois_info(), or None.
    Returns the path to the generated PDF, or None on failure.
    """
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("takedown_report.html.j2")

    whois_info = whois_info or {}

    screenshot_path = candidate.get("screenshot_path")
    screenshot_abs = None
    if screenshot_path and os.path.exists(screenshot_path):
        screenshot_abs = os.path.abspath(screenshot_path)

    reference_abs = None
    if os.path.exists(REFERENCE_SCREENSHOT_PATH):
        reference_abs = os.path.abspath(REFERENCE_SCREENSHOT_PATH)

    html_content = template.render(
        domain=candidate.get("domain"),
        decoded_domain=candidate.get("decoded_domain"),
        matched_brand=candidate.get("matched_brand"),
        detected_at=candidate.get("detected_at"),
        is_live=candidate.get("is_live"),
        visual_similarity=candidate.get("visual_similarity"),
        has_login_form=candidate.get("has_login_form"),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level") or "LOW",
        screenshot_path=screenshot_abs,
        reference_screenshot_path=reference_abs,
        registrar=whois_info.get("registrar"),
        creation_date=whois_info.get("creation_date"),
        emails=whois_info.get("emails"),
        name_servers=whois_info.get("name_servers"),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    safe_filename = candidate.get("domain", "unknown").replace(".", "_").replace("*", "wildcard")
    output_path = os.path.join(REPORT_OUTPUT_DIR, f"takedown_{safe_filename}.pdf")

    with open(output_path, "wb") as f:
        result = pisa.CreatePDF(html_content, dest=f)

    if result.err:
        print("PDF generation encountered errors.")
        return None

    return output_path


if __name__ == "__main__":
    sample_candidate = {
        "domain": "paypa1-secure.com",
        "decoded_domain": None,
        "matched_brand": "flipkart.com",
        "detected_at": "2026-09-09T10:00:00+00:00",
        "is_live": 1,
        "visual_similarity": 0.87,
        "has_login_form": 1,
        "risk_score": 93.25,
        "risk_level": "HIGH",
        "screenshot_path": "data/screenshots/flipkart_com.png",
    }

    sample_whois = {
        "registrar": "GoDaddy.com, LLC",
        "creation_date": "2026-09-08T12:00:00Z",
        "emails": ["abuse@godaddy.com"],
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    }

    path = generate_report(sample_candidate, sample_whois)
    print(f"Report generated: {path}")
