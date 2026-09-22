"""
risk_score.py
Combines individual enrichment signals into one composite risk score (0-100).

Phase 3: added has_mx / SPF+DMARC / SSL suspicion as extra signals.
Phase 4: visual_similarity now expects the COMBINED pHash+SSIM score
(from compute_combined_similarity), not pHash alone -- more resistant
to minor layout changes while still catching real visual cloning.
"""

WEIGHTS = {
    "is_live": 21,
    "visual_similarity": 30,
    "has_login_form": 21,
    "suspicious_phrases": 13,
    "has_mx": 5,
    "email_security": 5,
    "ssl_suspicious": 5,
}


def compute_risk_score(is_live, visual_similarity, has_login_form, suspicious_phrase_count=0,
                       has_mx=False, has_spf=False, has_dmarc=False, ssl_info=None):
    """
    Returns (total_score, breakdown_dict).
    total_score is 0-100. breakdown_dict shows each component's contribution.
    visual_similarity should be the combined pHash+SSIM score (0.0-1.0) as of Phase 4.
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

    mx_score = WEIGHTS["has_mx"] if has_mx else 0
    breakdown["has_mx"] = mx_score

    email_sec_score = WEIGHTS["email_security"] if (has_spf or has_dmarc) else 0
    breakdown["email_security"] = email_sec_score

    ssl_suspicious = bool(ssl_info and ssl_info.get("is_free_or_short_lived"))
    ssl_score = WEIGHTS["ssl_suspicious"] if ssl_suspicious else 0
    breakdown["ssl_suspicious"] = ssl_score

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
        {"name": "Dangerous fake phishing site (full signals)", "is_live": True, "visual_similarity": 0.95,
         "has_login_form": True, "suspicious_phrase_count": 2, "has_mx": True, "has_spf": True,
         "has_dmarc": False, "ssl_info": {"is_free_or_short_lived": True}},
        {"name": "Dead/unused domain", "is_live": False, "visual_similarity": 0.0, "has_login_form": False,
         "suspicious_phrase_count": 0, "has_mx": False, "has_spf": False, "has_dmarc": False, "ssl_info": None},
        {"name": "Live but unrelated site (e.g. github.com)", "is_live": True, "visual_similarity": 0.375,
         "has_login_form": False, "suspicious_phrase_count": 0, "has_mx": True, "has_spf": True,
         "has_dmarc": True, "ssl_info": {"is_free_or_short_lived": False}},
    ]

    for case in test_cases:
        score, breakdown = compute_risk_score(
            case["is_live"], case["visual_similarity"], case["has_login_form"],
            case["suspicious_phrase_count"], case["has_mx"], case["has_spf"],
            case["has_dmarc"], case["ssl_info"]
        )
        level = risk_level(score)
        print(f"\n{case['name']}")
        print(f"  Score: {score}/100  ({level})")
        print(f"  Breakdown: {breakdown}")
