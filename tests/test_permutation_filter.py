"""
test_permutation_filter.py
Tests for typosquat/homoglyph/combo-squat detection logic.
"""

from src.ingest.permutation_filter import (
    build_permutation_set, build_combo_squat_set, is_suspicious,
)

BRAND = "flipkart.com"


def test_real_domain_not_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious(BRAND, perms, official_domain=BRAND) is False


def test_homoglyph_typosquat_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("f1ipkart.com", perms, official_domain=BRAND) is True


def test_combo_squat_brand_then_keyword_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("flipkart-login.com", perms, official_domain=BRAND) is True


def test_combo_squat_keyword_then_brand_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("login-flipkart.com", perms, official_domain=BRAND) is True


def test_combo_squat_secure_keyword_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("flipkart-secure.com", perms, official_domain=BRAND) is True


def test_unrelated_domain_not_flagged():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("totally-unrelated.com", perms, official_domain=BRAND) is False


def test_is_suspicious_is_case_insensitive():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("FLIPKART-LOGIN.COM", perms, official_domain=BRAND) is True


def test_is_suspicious_strips_wildcard_prefix():
    perms = build_permutation_set(BRAND)
    assert is_suspicious("*.flipkart-login.com", perms, official_domain=BRAND) is True


def test_combo_squat_set_contains_expected_patterns():
    combos = build_combo_squat_set(BRAND)
    assert "flipkart-login.com" in combos
    assert "login-flipkart.com" in combos
    assert "flipkart-secure.com" in combos


def test_combo_squat_set_does_not_flag_real_domain():
    combos = build_combo_squat_set(BRAND)
    assert BRAND not in combos
