"""
pipeline.py
Blocking enrichment pipeline for ONE suspicious domain.
Called by async workers via asyncio.to_thread().
"""

from src.storage.db import (
    insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_risk_score,
)
from src.enrichment.dns_check import is_domain_live
from src.enrichment.screenshot import capture_screenshot
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.enrichment.punycode_decoder import decode_domain
from src.enrichment.whois_lookup import get_whois_info
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert
from src.reporting.report_generator import generate_report


def process_candidate(domain, official_domain):
    def log(msg):
        print(f"[{domain}] {msg}", flush=True)

    log("SUSPICIOUS MATCH")

    decoded, is_puny = decode_domain(domain)
    if is_puny:
        log(f"Decoded (Punycode): {decoded}")

    candidate_id = insert_candidate(
        domain, official_domain, decoded_domain=decoded if is_puny else None
    )

    live = is_domain_live(domain)
    update_liveness(candidate_id, live)
    log(f"DNS check: {'LIVE' if live else 'not live'}")

    similarity = None
    has_login = False
    phrase_count = 0
    screenshot_path = None

    if live:
        screenshot_path = capture_screenshot(domain)
        if screenshot_path:
            update_screenshot_path(candidate_id, screenshot_path)
            similarity = compute_similarity(screenshot_path)
            if similarity is not None:
                update_visual_similarity(candidate_id, similarity)
                log(f"Visual similarity: {similarity}")

        html = fetch_page_html(domain)
        content_result = analyze_content(html)
        has_login = content_result["has_login_form"]
        phrase_count = len(content_result["suspicious_phrases_found"])
        update_content_signals(candidate_id, has_login)
        log(f"Login form detected: {has_login}")

    score, breakdown = compute_risk_score(live, similarity, has_login, phrase_count)
    level = risk_level(score)
    update_risk_score(candidate_id, score, level)
    log(f"RISK SCORE: {score}/100 ({level})")

    if level == "HIGH":
        sent = send_alert(domain, score, level, official_domain)
        log(f"Telegram alert sent: {sent}")

        whois_info = get_whois_info(domain)
        candidate_record = {
            "domain": domain,
            "decoded_domain": decoded if is_puny else None,
            "matched_brand": official_domain,
            "detected_at": "just now",
            "is_live": live,
            "visual_similarity": similarity,
            "has_login_form": has_login,
            "risk_score": score,
            "risk_level": level,
            "screenshot_path": screenshot_path,
        }
        report_path = generate_report(candidate_record, whois_info)
        log(f"Takedown report generated: {report_path}")
