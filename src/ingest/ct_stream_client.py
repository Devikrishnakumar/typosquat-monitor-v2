"""
ct_stream_client.py
Full pipeline: CT stream -> typosquat filter -> punycode decode -> DNS check ->
screenshot -> visual similarity -> content signals -> composite risk score ->
Telegram alert + takedown report (HIGH risk only) -> SQLite storage.
Automatically captures/refreshes the brand reference screenshot on startup.
"""

import argparse
import json
import websocket

from .permutation_filter import get_brand_settings, build_permutation_set, is_suspicious
from src.storage.db import (
    init_db, insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_risk_score
)
from src.enrichment.dns_check import is_domain_live
from src.enrichment.screenshot import capture_screenshot, ensure_reference_screenshot
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.enrichment.punycode_decoder import decode_domain
from src.enrichment.whois_lookup import get_whois_info
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert
from src.reporting.report_generator import generate_report

CERTSTREAM_URL = "ws://localhost:8081/full-stream"


def on_message(ws, message, permutation_set, official_domain):
    try:
        data = json.loads(message)

        if data.get("message_type") != "certificate_update":
            return

        leaf_cert = data["data"]["leaf_cert"]
        domains = leaf_cert.get("all_domains", [])

        for domain in domains:
            if is_suspicious(domain, permutation_set, official_domain=official_domain):
                print(f"[SUSPICIOUS MATCH] {domain}")

                decoded, is_puny = decode_domain(domain)
                if is_puny:
                    print(f"  -> Decoded (Punycode): {decoded}")

                candidate_id = insert_candidate(domain, official_domain, decoded_domain=decoded if is_puny else None)

                live = is_domain_live(domain)
                update_liveness(candidate_id, live)
                print(f"  -> DNS check: {'LIVE' if live else 'not live'}")

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
                            print(f"  -> Visual similarity: {similarity}")

                    html = fetch_page_html(domain)
                    content_result = analyze_content(html)
                    has_login = content_result["has_login_form"]
                    phrase_count = len(content_result["suspicious_phrases_found"])
                    update_content_signals(candidate_id, has_login)
                    print(f"  -> Login form detected: {has_login}")

                score, breakdown = compute_risk_score(live, similarity, has_login, phrase_count)
                level = risk_level(score)
                update_risk_score(candidate_id, score, level)
                print(f"  -> RISK SCORE: {score}/100 ({level})")

                if level == "HIGH":
                    sent = send_alert(domain, score, level, official_domain)
                    print(f"  -> Telegram alert sent: {sent}")

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
                    print(f"  -> Takedown report generated: {report_path}")

    except Exception as e:
        print(f"Error processing message: {e}")


def on_error(ws, error):
    print(f"Websocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    print("Connection closed.")


def on_open(ws):
    print("Connected to certstream-server-go. Watching for typosquat matches...\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    args = parser.parse_args()

    init_db()

    official_domain = get_brand_settings(cli_brand=args.brand)
    permutation_set = build_permutation_set(official_domain)

    # Automatically ensure the reference screenshot matches the currently
    # monitored brand -- no manual screenshot step required.
    ensure_reference_screenshot(official_domain)

    print(f"\nMonitoring for typosquats of: {official_domain}")
    print(f"Loaded {len(permutation_set)} permutations to watch for.\n")

    ws = websocket.WebSocketApp(
        CERTSTREAM_URL,
        on_open=on_open,
        on_message=lambda ws, msg: on_message(ws, msg, permutation_set, official_domain),
        on_error=on_error,
        on_close=on_close,
    )
    ws.run_forever()
