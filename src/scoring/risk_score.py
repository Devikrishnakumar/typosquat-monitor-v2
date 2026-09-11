"""
risk_score.py
Combines individual enrichment signals into one composite risk score (0-100).
"""

WEIGHTS = {
    "is_live": 25,
    "visual_similarity": 35,
    "has_login_form": 25,
    "suspicious_phrases": 15,
}


def compute_risk_score(is_live, visual_similarity, has_login_form, suspicious_phrase_count=0):
    """
    Returns (total_score, breakdown_dict).
    total_score is 0-100. breakdown_dict shows each component's contribution.
    """
    breakdown = {}

    live_score = WEIGHTS["is_live"] if is_live else 0
    breakdown["is_live"] = live_score

    similarity_score = float(visual_similarity or 0) * WEIGHTS["visual_similarity"]
    breakdown["visual_similarity"] = round(similarity_score, 2)

    login_score = WEIGHTS["has_login_form"] if has_login_form else 0
    breakdown["has_login_form"] = login_score

    phrase_score = min(suspicious_phrase_count, 3) / 3 * WEIGHTS["suspicious_phrases"]
    breakdown["suspicious_phrases"] = round(phrase_score, 2)

    total = sum(breakdown.values())
    total = round(min(total, 100), 2)

    return total, breakdown


def risk_level(score):
    """Returns a severity label based on score."""
    if score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    else:
        return "LOW"


if __name__ == "__main__":
    test_cases = [
        {"name": "Dangerous fake phishing site", "is_live": True, "visual_similarity": 0.95, "has_login_form": True, "suspicious_phrase_count": 2},
        {"name": "Dead/unused domain", "is_live": False, "visual_similarity": 0.0, "has_login_form": False, "suspicious_phrase_count": 0},
        {"name": "Live but unrelated site (e.g. github.com)", "is_live": True, "visual_similarity": 0.375, "has_login_form": False, "suspicious_phrase_count": 0},
    ]

    for case in test_cases:
        score, breakdown = compute_risk_score(
            case["is_live"], case["visual_similarity"],
            case["has_login_form"], case["suspicious_phrase_count"]
        )
        level = risk_level(score)
        print(f"\n{case['name']}")
        print(f"  Score: {score}/100  ({level})")
        print(f"  Breakdown: {breakdown}")
