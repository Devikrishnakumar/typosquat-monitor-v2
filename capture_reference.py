from src.enrichment.screenshot import capture_screenshot

path = capture_screenshot("flipkart.com")
print(f"Reference screenshot saved to: {path}")
