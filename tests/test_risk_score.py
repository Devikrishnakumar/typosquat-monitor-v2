"""
test_risk_score.py
Tests for composite risk score calculation and severity levels.
"""

from src.scoring.risk_score import compute_risk_score, risk_level


def test_dead_domain_scores_zero():
    score, breakdown = compute_risk_score(
        is_live=False, visual_similarity=0.0, has_login_form=False,
    )
    assert score == 0.0
    assert risk_level(score) == "LOW"


def test_full_signals_scores_high():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=0.95, has_login_form=True,
        suspicious_phrase_count=2, has_mx=True, has_spf=True, has_dmarc=False,
        ssl_info={"is_free_or_short_lived": True},
    )
    assert score >= 70
    assert risk_level(score) == "HIGH"


def test_score_never_exceeds_100():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=1.0, has_login_form=True,
        suspicious_phrase_count=99, has_mx=True, has_spf=True, has_dmarc=True,
        ssl_info={"is_free_or_short_lived": True},
    )
    assert score <= 100


def test_risk_level_boundaries():
    assert risk_level(70) == "HIGH"
    assert risk_level(69.99) == "MEDIUM"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(49.99) == "LOW"
    assert risk_level(0) == "LOW"


def test_missing_ssl_info_does_not_crash():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=0.5, has_login_form=False, ssl_info=None,
    )
    assert breakdown["ssl_suspicious"] == 0


def test_none_visual_similarity_treated_as_zero():
    score, breakdown = compute_risk_score(
        is_live=True, visual_similarity=None, has_login_form=False,
    )
    assert breakdown["visual_similarity"] == 0.0
