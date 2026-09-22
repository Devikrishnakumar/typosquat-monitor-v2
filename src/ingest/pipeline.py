"""
pipeline.py
Blocking enrichment pipeline for ONE suspicious domain.
Called by async workers via asyncio.to_thread().

Phase 3: added MX / SPF+DMARC / SSL metadata / favicon hash checks.
Phase 4: visual similarity now uses compute_combined_similarity()
(pHash + SSIM blended), more resistant to minor layout changes.
"""

from src.storage.db import (
    insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_risk_score,
    update_email_security, update_ssl_metadata, update_favicon_hash,
    update_ssim_similarity,
)
from src.enrichment.dns_check import is_domain_live
from src.enrichment.screenshot import capture_screenshot
from src.enrichment.visual_similarity import compute_combined_similarity
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.enrichment.punycode_decoder import decode_domain
from src.enrichment.whois_lookup import get_whois_info
from src.enrichment.mx_check import has_mx_records
from src.enrichment.email_security import check_email_security
from src.enrichment.ssl_metadata import get_ssl_metadata
from src.enrichment.favicon_hash import get_favicon_hash
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

    combined_similarity = None
    has_login = False
    phrase_count = 0
    screenshot_path = None

    if live:
        screenshot_path = capture_screenshot(domain)
        if screenshot_path:
            update_screenshot_path(candidate_id, screenshot_path)
            sim_result = compute_combined_similarity(screenshot_path)
            phash_score = sim_result["phash_similarity"]
            ssim_score = sim_result["ssim_similarity"]
            combined_similarity = sim_result["combined_similarity"]

            if phash_score is not None:
                update_visual_similarity(candidate_id, phash_score)
            update_ssim_similarity(candidate_id, ssim_score, combined_similarity)

            log(f"Visual similarity -> pHash: {phash_score}, SSIM: {ssim_score}, "
                f"combined: {combined_similarity}")

        html = fetch_page_html(domain)
        content_result = analyze_content(html)
        has_login = content_result["has_login_form"]
        phrase_count = len(content_result["suspicious_phrases_found"])
        update_content_signals(candidate_id, has_login)
        log(f"Login form detected: {has_login}")

    # Phase 3: MX / SPF / DMARC / SSL / favicon signals (checked whether live or not --
    # MX/SPF/DMARC live on DNS, not the webserver, so they can exist even if the site itself is down)
    has_mx = has_mx_records(domain)
    email_sec = check_email_security(domain)
    has_spf = email_sec["has_spf"]
    has_dmarc = email_sec["has_dmarc"]
    update_email_security(candidate_id, has_mx, has_spf, has_dmarc)
    log(f"MX: {has_mx}, SPF: {has_spf}, DMARC: {has_dmarc}")

    ssl_info = get_ssl_metadata(domain)
    update_ssl_metadata(candidate_id, ssl_info)
    if ssl_info:
        log(f"SSL issuer: {ssl_info['issuer']}, SANs: {ssl_info['san_count']}, "
            f"free/short-lived: {ssl_info['is_free_or_short_lived']}")

    favicon_hash = get_favicon_hash(domain)
    update_favicon_hash(candidate_id, favicon_hash)
    log(f"Favicon hash: {favicon_hash}")

    score, breakdown = compute_risk_score(
        live, combined_similarity, has_login, phrase_count,
        has_mx=has_mx, has_spf=has_spf, has_dmarc=has_dmarc, ssl_info=ssl_info,
    )
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
            "visual_similarity": combined_similarity,
            "has_login_form": has_login,
            "risk_score": score,
            "risk_level": level,
            "screenshot_path": screenshot_path,
        }
        report_path = generate_report(candidate_record, whois_info)
        log(f"Takedown report generated: {report_path}")
