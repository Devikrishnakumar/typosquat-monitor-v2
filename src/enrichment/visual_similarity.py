"""
visual_similarity.py
Compares a candidate domain's screenshot against the brand's reference
screenshot using perceptual hashing (pHash), and returns a similarity score.
"""

import imagehash
from PIL import Image

REFERENCE_IMAGE_PATH = "reference_assets/brand_reference_screenshot.png"


def compute_similarity(candidate_screenshot_path, reference_path=REFERENCE_IMAGE_PATH):
    """
    Returns a similarity score between 0.0 (completely different) and
    1.0 (identical), based on perceptual hash distance.
    """
    try:
        reference_img = Image.open(reference_path)
        candidate_img = Image.open(candidate_screenshot_path)

        reference_hash = imagehash.phash(reference_img)
        candidate_hash = imagehash.phash(candidate_img)

        distance = reference_hash - candidate_hash
        similarity = 1 - (distance / 64)

        return round(similarity, 4)

    except Exception as e:
        print(f"Error computing similarity: {e}")
        return None


if __name__ == "__main__":
    from src.enrichment.screenshot import capture_screenshot

    print("Test 1: reference vs itself")
    score = compute_similarity(REFERENCE_IMAGE_PATH)
    print(f"  Similarity: {score} (expect ~1.0)")

    print("\nTest 2: reference vs google.com")
    google_shot = capture_screenshot("google.com")
    if google_shot:
        score = compute_similarity(google_shot)
        print(f"  Similarity: {score} (expect low, e.g. <0.5)")
