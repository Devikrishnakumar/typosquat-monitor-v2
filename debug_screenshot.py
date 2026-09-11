from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    try:
        page.goto("https://flipkart.com", timeout=15000, wait_until="load")
        page.screenshot(path="test_flipkart.png")
        print("SUCCESS")
    except Exception as e:
        print("ERROR:", type(e).__name__, str(e)[:300])
    browser.close()
