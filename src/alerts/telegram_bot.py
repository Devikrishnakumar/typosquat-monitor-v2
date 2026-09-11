"""
telegram_bot.py
Sends a Telegram alert when a HIGH-risk typosquat domain is detected.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_alert(domain, risk_score, risk_level, matched_brand, retries=2):
    """
    Sends a formatted alert message to Telegram.
    Retries on timeout/connection errors. Returns True on success, False otherwise.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram credentials not configured, skipping alert.")
        return False

    message = (
        f"🚨 *{risk_level} RISK TYPOSQUAT DETECTED*\n\n"
        f"Domain: `{domain}`\n"
        f"Impersonating: `{matched_brand}`\n"
        f"Risk Score: *{risk_score}/100*\n"
    )

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    for attempt in range(1, retries + 2):
        try:
            response = requests.post(url, data=payload, timeout=20)
            if response.status_code == 200:
                return True
            print(f"Telegram returned status {response.status_code}, attempt {attempt}")
        except Exception as e:
            print(f"Telegram alert attempt {attempt} failed: {e}")

        if attempt < retries + 1:
            time.sleep(2)

    return False


if __name__ == "__main__":
    success = send_alert(
        domain="paypa1-secure.com",
        risk_score=93.25,
        risk_level="HIGH",
        matched_brand="paypal.com",
    )
    print(f"Alert sent: {success}")
