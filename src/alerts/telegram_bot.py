"""
Telegram alert delivery for live detections and controlled simulations.
"""

import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_alert(
    domain,
    risk_score,
    risk_level,
    matched_brand,
    retries=2,
    source="LIVE",
    match_id=None,
    risk_reason=None,
):
    """Send a HIGH-risk Telegram alert."""

    level = str(risk_level or "").upper()
    if level not in {"MEDIUM", "HIGH"}:
        print("Telegram alert skipped: risk is not MEDIUM or HIGH.")
        return False

    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram credentials not configured, skipping alert.")
        return False

    source = str(source or "LIVE").upper()

    if source == "SIMULATION":
        title = f"SIMULATION {level}-RISK TYPOSQUAT ALERT"
    else:
        title = f"LIVE {level}-RISK TYPOSQUAT ALERT"

    message = (
        f"*{title}*\n\n"
        f"Domain: `{domain}`\n"
        f"Impersonating: `{matched_brand}`\n"
        f"Risk Score: *{risk_score}/100*\n"
    )

    if match_id:
        message += f"Match ID: `{match_id}`\n"

    if risk_reason:
        message += f"Reason: {risk_reason}\n"

    message += f"Source: *{source}*"

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    for attempt in range(1, retries + 2):
        try:
            response = requests.post(
                url,
                data=payload,
                timeout=20,
            )

            if response.status_code == 200:
                print(f"{source} Telegram alert delivered.")
                return True

            print(
                f"Telegram returned status "
                f"{response.status_code}, attempt {attempt}"
            )

        except Exception as exc:
            print(f"Telegram alert attempt {attempt} failed: {exc}")

        if attempt < retries + 1:
            time.sleep(2)

    return False


def send_live_alert(candidate):
    """Send an alert for a real live detection."""

    return send_alert(
        domain=candidate.get("domain"),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level"),
        matched_brand=candidate.get("matched_brand"),
        source="LIVE",
    )


def send_simulation_alert(candidate):
    """Send a clearly labelled alert for a simulated HIGH-risk match."""

    if not candidate.get("simulation", False):
        print("Simulation alert skipped: not a simulation.")
        return False

    return send_alert(
        domain=(
            candidate.get("display_domain")
            or candidate.get("domain")
        ),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level"),
        matched_brand=candidate.get("matched_brand"),
        source="SIMULATION",
        match_id=candidate.get("match_id"),
        risk_reason=candidate.get("risk_reason"),
    )
