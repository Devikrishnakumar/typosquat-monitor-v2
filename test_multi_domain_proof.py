"""
Repopulates test data through the FULL pipeline including risk scoring,
using different real domains to show varied risk levels on the dashboard.
"""

from src.storage.db import (
    init_db, insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_risk_score
)
from src.enrichment.dns_check import is_domain_live
from src.enrichment.screenshot import capture_screenshot
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.scoring.risk_score import compute_risk_score, risk_level

init_db()

test_domains = ["github.com", "wikipedia.org", "python.org"]

for domain in test_domains:
    print(f"\nProcessing {domain}...")
    candidate_id = insert_candidate(domain, matched_brand="demo-run")

    live = is_domain_live(domain)
    update_liveness(candidate_id, live)

    similarity = None
    has_login = False

    if live:
        screenshot_path = capture_screenshot(domain)
        if screenshot_path:
            update_screenshot_path(candidate_id, screenshot_path)
            similarity = compute_similarity(screenshot_path)
            if similarity is not None:
                update_visual_similarity(candidate_id, similarity)

        html = fetch_page_html(domain)
        result = analyze_content(html)
        has_login = result["has_login_form"]
        update_content_signals(candidate_id, has_login)

    score, breakdown = compute_risk_score(live, similarity, has_login, 0)
    level = risk_level(score)
    update_risk_score(candidate_id, score, level)
    print(f"  Risk: {score}/100 ({level})")

print("\nDone. Refresh your dashboard.")
