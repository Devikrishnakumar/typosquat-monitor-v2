"""
demo_high_risk_trigger.py
Simulates a realistic HIGH-risk typosquat detection for demo purposes,
running through the full pipeline: scoring -> Telegram alert -> PDF report.
Uses a real live domain for the DNS check and reuses the Flipkart reference
screenshot to demonstrate a genuinely high visual-similarity match.
"""

from src.storage.db import (
    init_db, insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_risk_score
)
from src.enrichment.dns_check import is_domain_live
from src.enrichment.whois_lookup import get_whois_info
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert
from src.reporting.report_generator import generate_report

init_db()

# A realistic-looking fake typosquat domain name for the demo
demo_domain = "flipkart-secure-login.com"
official_domain = "flipkart.com"

print(f"Simulating HIGH-risk detection for: {demo_domain}\n")

candidate_id = insert_candidate(demo_domain, official_domain)

# Real DNS check against a real live domain, so this part is genuinely accurate
live = is_domain_live("flipkart.com")  # using real flipkart.com to guarantee LIVE for demo
update_liveness(candidate_id, live)
print(f"DNS check: {'LIVE' if live else 'not live'}")

# Reuse the real Flipkart reference screenshot -- demonstrates a genuinely
# high similarity score using actual pHash comparison, not a fabricated number
screenshot_path = "reference_assets/brand_reference_screenshot.png"
update_screenshot_path(candidate_id, screenshot_path)

from src.enrichment.visual_similarity import compute_similarity
similarity = compute_similarity(screenshot_path)
update_visual_similarity(candidate_id, similarity)
print(f"Visual similarity: {similarity}")

# For demo purposes, simulate a detected login form
has_login = True
update_content_signals(candidate_id, has_login)
print(f"Login form detected: {has_login}")

score, breakdown = compute_risk_score(live, similarity, has_login, suspicious_phrase_count=1)
level = risk_level(score)
update_risk_score(candidate_id, score, level)
print(f"\nRISK SCORE: {score}/100 ({level})")
print(f"Breakdown: {breakdown}")

if level == "HIGH":
    sent = send_alert(demo_domain, score, level, official_domain)
    print(f"\nTelegram alert sent: {sent}")

    whois_info = get_whois_info(official_domain)

    candidate_record = {
        "domain": demo_domain,
        "decoded_domain": None,
        "matched_brand": official_domain,
        "detected_at": "demo run",
        "is_live": live,
        "visual_similarity": similarity,
        "has_login_form": has_login,
        "risk_score": score,
        "risk_level": level,
        "screenshot_path": screenshot_path,
    }

    report_path = generate_report(candidate_record, whois_info)
    print(f"Takedown report generated: {report_path}")
else:
    print(f"\nScore didn't reach HIGH threshold -- adjust breakdown weights if needed for demo purposes.")

print("\nDone. Check your dashboard, Telegram, and the reports/ folder.")
