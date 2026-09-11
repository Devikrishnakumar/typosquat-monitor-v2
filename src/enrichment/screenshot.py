"""
screenshot.py
Captures a screenshot of a live domain using Playwright headless Chromium.
Also handles automatically capturing/refreshing the brand's reference screenshot,
and tracks which brand the current reference belongs to.
"""

import os
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = "data/screenshots"
REFERENCE_PATH = "reference_assets/brand_reference_screenshot.png"
REFERENCE_META_PATH = "reference_assets/brand_reference_meta.txt"


def capture_screenshot(domain, timeout_ms=20000):
    """
    Attempts to load the domain over HTTPS (falls back to HTTP) and
    saves a screenshot. Returns the file path on success, None on failure.
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    safe_filename = domain.replace(".", "_").replace("*", "wildcard")
    output_path = os.path.join(SCREENSHOT_DIR, f"{safe_filename}.png")

    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})

        for url in urls_to_try:
            try:
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                page.screenshot(path=output_path)
                browser.close()
                return output_path
            except Exception:
                continue

        browser.close()
        return None


def ensure_reference_screenshot(official_domain):
    """
    Ensures a reference screenshot exists for the CURRENTLY monitored brand.
    Automatically captures a fresh one if:
      - no reference screenshot exists yet, OR
      - the existing reference belongs to a different brand (tracked via a
        small metadata file), which happens when --brand is switched.
    Returns the reference screenshot path, or None on failure.
    """
    os.makedirs("reference_assets", exist_ok=True)

    existing_brand = None
    if os.path.exists(REFERENCE_META_PATH):
        with open(REFERENCE_META_PATH, "r") as f:
            existing_brand = f.read().strip()

    if os.path.exists(REFERENCE_PATH) and existing_brand == official_domain:
        print(f"Using existing reference screenshot for {official_domain}")
        return REFERENCE_PATH

    print(f"Capturing new reference screenshot for {official_domain} (brand changed or reference missing)...")
    captured_path = capture_screenshot(official_domain)

    if captured_path:
        import shutil
        shutil.copy(captured_path, REFERENCE_PATH)
        with open(REFERENCE_META_PATH, "w") as f:
            f.write(official_domain)
        print(f"Reference screenshot saved for {official_domain}: {REFERENCE_PATH}")
        return REFERENCE_PATH
    else:
        print(f"WARNING: Could not capture reference screenshot for {official_domain}.")
        return None


if __name__ == "__main__":
    test_domains = ["example.com", "google.com", "flipkart.com", "this-domain-should-not-exist-xyz123.com"]

    for domain in test_domains:
        result = capture_screenshot(domain)
        if result:
            print(f"{domain:40s} -> saved to {result}")
        else:
            print(f"{domain:40s} -> FAILED (no screenshot)")
