"""
webhook_dispatcher.py
Sends alert payloads to all registered webhooks matching a candidate's risk level.
Compatible with generic JSON consumers, Slack incoming webhooks, and Microsoft
Teams incoming webhooks (both accept a JSON POST body).
"""

import requests

from src.storage.db import get_webhooks_for_risk_level


def _build_payload(candidate_dict):
    """
    Generic JSON payload. Also includes a 'text' field so Slack/Teams
    incoming webhooks render something readable without extra formatting.
    """
    domain = candidate_dict.get("domain")
    brand = candidate_dict.get("matched_brand")
    score = candidate_dict.get("risk_score")
    level = candidate_dict.get("risk_level")

    summary = (
        f"[{level}] Typosquat candidate detected: {domain} "
        f"(impersonating {brand}, risk score {score}/100)"
    )

    return {
        "text": summary,               # Slack/Teams render this directly
        "summary": summary,            # Teams sometimes expects this key instead
        "candidate": candidate_dict,   # full structured data for custom/SIEM consumers
    }


def send_webhook_alerts(candidate_dict, timeout=10):
    """
    Sends the candidate's alert to every webhook whose min_risk_level
    threshold is met by this candidate's risk_level. Returns a list of
    (webhook_id, url, success, error) tuples for logging.
    """
    risk_level = candidate_dict.get("risk_level")
    webhooks = get_webhooks_for_risk_level(risk_level)

    if not webhooks:
        return []

    payload = _build_payload(candidate_dict)
    results = []

    for wh in webhooks:
        try:
            resp = requests.post(wh["url"], json=payload, timeout=timeout)
            success = resp.status_code < 400
            error = None if success else f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            success = False
            error = str(e)

        results.append((wh["id"], wh["url"], success, error))

    return results


if __name__ == "__main__":
    # Smoke test with a fake HIGH-risk candidate (uses httpbin as a dummy endpoint)
    from src.storage.db import register_webhook, delete_webhook

    wh = register_webhook("https://httpbin.org/post", label="Test endpoint", min_risk_level="HIGH")
    print("Registered test webhook:", wh)

    fake_candidate = {
        "id": 999, "domain": "paypa1-fake.com", "matched_brand": "paypal.com",
        "risk_score": 92.5, "risk_level": "HIGH",
    }

    results = send_webhook_alerts(fake_candidate)
    print("Dispatch results:", results)

    delete_webhook(wh["id"])
    print("Cleaned up test webhook.")
