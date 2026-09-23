"""
visual_similarity.py
Compares a candidate domain's screenshot against the brand's reference
screenshot using two methods:
  1. Perceptual hashing (pHash) -- fast, but sensitive to minor layout shifts.
  2. SSIM (Structural Similarity Index) -- compares structural patterns
     (edges/luminance/contrast), more forgiving of small layout changes
     while still catching real visual cloning.
compute_similarity() (pHash only) is kept unchanged for backward compatibility.
compute_combined_similarity() runs both and returns a blended score.
"""

import imagehash
import cv2
from PIL import Image
from skimage.metrics import structural_similarity as ssim

REFERENCE_IMAGE_PATH = "reference_assets/brand_reference_screenshot.png"

SSIM_TARGET_SIZE = (400, 300)  # resize both images to this before SSIM, for a fair pixel-level comparison


def compute_similarity(candidate_screenshot_path, reference_path=REFERENCE_IMAGE_PATH):
    """
    Original pHash-based similarity. Returns a score between 0.0 and 1.0.
    Kept unchanged so existing callers are unaffected.
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
        print(f"Error computing pHash similarity: {e}")
        return None


def compute_ssim_similarity(candidate_screenshot_path, reference_path=REFERENCE_IMAGE_PATH):
    """
    SSIM-based similarity. Returns a score between 0.0 (completely different)
    and 1.0 (identical structure), or None on failure.
    """
    try:
        ref_img = cv2.imread(reference_path)
        cand_img = cv2.imread(candidate_screenshot_path)

        if ref_img is None or cand_img is None:
            return None

        ref_resized = cv2.resize(ref_img, SSIM_TARGET_SIZE)
        cand_resized = cv2.resize(cand_img, SSIM_TARGET_SIZE)

        ref_gray = cv2.cvtColor(ref_resized, cv2.COLOR_BGR2GRAY)
        cand_gray = cv2.cvtColor(cand_resized, cv2.COLOR_BGR2GRAY)

        score, _ = ssim(ref_gray, cand_gray, full=True)
        # SSIM can return slightly negative values for very different images; clamp to 0
        return round(max(0.0, min(1.0, score)), 4)

    except Exception as e:
        print(f"Error computing SSIM similarity: {e}")
        return None


def compute_combined_similarity(candidate_screenshot_path, reference_path=REFERENCE_IMAGE_PATH):
    """
    Runs both pHash and SSIM and returns a dict with both scores plus a
    blended score (simple average of the two, ignoring whichever failed).
    """
    phash_score = compute_similarity(candidate_screenshot_path, reference_path)
    ssim_score = compute_ssim_similarity(candidate_screenshot_path, reference_path)

    scores = [s for s in (phash_score, ssim_score) if s is not None]
    combined = round(sum(scores) / len(scores), 4) if scores else None

    return {
        "phash_similarity": phash_score,
        "ssim_similarity": ssim_score,
        "combined_similarity": combined,
    }


if __name__ == "__main__":
    from src.enrichment.screenshot import capture_screenshot

    print("Test 1: reference vs itself")
    result = compute_combined_similarity(REFERENCE_IMAGE_PATH)
    print(f"  {result} (expect all ~1.0)")

    print("\nTest 2: reference vs google.com")
    google_shot = capture_screenshot("google.com")
    if google_shot:
        result = compute_combined_similarity(google_shot)
        print(f"  {result} (expect low combined, e.g. <0.5)")
