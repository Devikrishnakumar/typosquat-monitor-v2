"""
report_generator.py

Generates PDF reports for normal detections and simulation evidence.
Simulation reports are explicitly labelled as simulation material.
"""

import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa


TEMPLATE_DIR = "src/reporting/templates"
REPORT_OUTPUT_DIR = "reports"
REFERENCE_SCREENSHOT_PATH = "reference_assets/brand_reference_screenshot.png"


def _absolute_existing(path):
    if not path:
        return None

    if not os.path.exists(path):
        return None

    return os.path.abspath(path)


def generate_report(
    candidate,
    whois_info=None,
    simulation_evidence=None,
):
    """
    candidate:
        Dictionary representing the selected candidate.

    whois_info:
        Registrar/RDAP information.

    simulation_evidence:
        Optional dictionary returned by run_simulation().

    Returns:
        PDF path, or None on failure.
    """

    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR)
    )

    template = env.get_template(
        "takedown_report.html.j2"
    )

    whois_info = whois_info or {}
    simulation_evidence = simulation_evidence or {}

    is_simulation = bool(
        simulation_evidence.get("simulation")
    )

    default_reference = _absolute_existing(
        REFERENCE_SCREENSHOT_PATH
    )

    candidate_screenshot = _absolute_existing(
        candidate.get("screenshot_path")
    )

    reference_home_screenshot = _absolute_existing(
        simulation_evidence.get(
            "reference_home_screenshot"
        )
    ) or default_reference

    suspicious_home_screenshot = _absolute_existing(
        simulation_evidence.get(
            "candidate_home_screenshot"
        )
    ) or candidate_screenshot

    reference_login_screenshot = _absolute_existing(
        simulation_evidence.get(
            "reference_login_screenshot"
        )
    )

    candidate_login_screenshot = _absolute_existing(
        simulation_evidence.get(
            "candidate_login_screenshot"
        )
    )

    render_data = {
        "domain": candidate.get("domain"),
        "decoded_domain": candidate.get("decoded_domain"),
        "matched_brand": candidate.get("matched_brand"),
        "detected_at": candidate.get("detected_at"),
        "is_live": candidate.get("is_live"),
        "visual_similarity": (
            simulation_evidence.get("visual_similarity")
            if is_simulation
            else candidate.get("visual_similarity")
        ),
        "has_login_form": (
            simulation_evidence
            .get("candidate_login", {})
            .get("login_form")
            if is_simulation
            else candidate.get("has_login_form")
        ),
        "risk_score": (
            candidate.get("risk_score")
            if is_simulation
            else candidate.get("risk_score")
        ),
        "risk_level": (
            candidate.get("risk_level")
            if is_simulation
            else candidate.get("risk_level")
        ) or "LOW",

        "evidence_risk_score": (
            simulation_evidence.get("risk_score")
            if is_simulation
            else None
        ),

        "evidence_risk_level": (
            simulation_evidence.get("risk_level")
            if is_simulation
            else None
        ),

        "screenshot_path": suspicious_home_screenshot,
        "reference_screenshot_path": reference_home_screenshot,

        "registrar": whois_info.get("registrar"),
        "creation_date": whois_info.get("creation_date"),
        "emails": whois_info.get("emails"),
        "name_servers": whois_info.get("name_servers"),

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "is_simulation": is_simulation,

        "official_domain": simulation_evidence.get(
            "official_domain"
        ),

        "production_risk_score": simulation_evidence.get(
            "production_risk_score"
        ),

        "production_risk_level": simulation_evidence.get(
            "production_risk_level"
        ),

        "reference_login_screenshot_path":
            reference_login_screenshot,

        "candidate_login_screenshot_path":
            candidate_login_screenshot,

        "login_similarity":
            simulation_evidence.get("login_similarity"),

        "candidate_login":
            simulation_evidence.get("candidate_login", {}),

        "reference_login":
            simulation_evidence.get("reference_login", {}),

        "login_comparison":
            simulation_evidence.get("login_comparison", {}),

        "risk_breakdown":
            simulation_evidence.get("risk_breakdown", {}),

        "certificate_source":
            "Certificate Transparency (CT) stream",

        "certificate_details_note":
            "The current candidates table stores the detected domain and enrichment results, but not raw certificate serial/issuer fields. Therefore this report records CT as the detection source without inventing certificate metadata.",

        "detection_pipeline": [
            "Certificate Transparency stream ingestion",
            "Typosquat / permutation matching",
            "Domain and DNS enrichment",
            "Playwright website capture",
            "Visual similarity analysis",
            "Rendered HTML/content analysis",
            "Login-page comparison",
            "Composite risk scoring",
            "Evidence PDF generation",
        ],
    }

    html_content = template.render(
        **render_data
    )

    safe_filename = str(
        candidate.get("domain", "unknown")
    ).replace(".", "_").replace("*", "wildcard")

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    if is_simulation:
        filename = (
            f"simulation_report_"
            f"{safe_filename}_"
            f"{timestamp}.pdf"
        )
    else:
        filename = (
            f"takedown_"
            f"{safe_filename}.pdf"
        )

    output_path = os.path.join(
        REPORT_OUTPUT_DIR,
        filename,
    )

    with open(
        output_path,
        "wb",
    ) as f:
        result = pisa.CreatePDF(
            html_content,
            dest=f,
        )

    if result.err:
        print(
            "PDF generation encountered errors."
        )
        return None

    return output_path


if __name__ == "__main__":
    sample_candidate = {
        "domain": "paypa1-secure.com",
        "decoded_domain": None,
        "matched_brand": "paypal.com",
        "detected_at": "2026-09-09T10:00:00+00:00",
        "is_live": 1,
        "visual_similarity": 0.87,
        "has_login_form": 1,
        "risk_score": 93.25,
        "risk_level": "HIGH",
        "screenshot_path": "data/screenshots/paypal_com.png",
    }

    path = generate_report(
        sample_candidate,
        {},
    )

    print(
        f"Report generated: {path}"
    )
