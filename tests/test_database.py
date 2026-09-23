"""
test_database.py
Tests for the SQLAlchemy storage layer: candidate CRUD, lifecycle,
audit trail, and webhook management.
"""

import pytest

from src.storage.db import (
    insert_candidate, update_liveness, update_risk_score,
    update_status, add_note, get_candidate, get_events,
    get_all_candidates, get_candidates,
    register_webhook, get_webhooks, delete_webhook, get_webhooks_for_risk_level,
)


def test_insert_and_get_candidate():
    cid = insert_candidate("fake-login.com", "realbrand.com")
    c = get_candidate(cid)
    assert c["domain"] == "fake-login.com"
    assert c["matched_brand"] == "realbrand.com"
    assert c["status"] == "new"


def test_update_liveness_and_risk_score():
    cid = insert_candidate("fake-login.com", "realbrand.com")
    update_liveness(cid, True)
    update_risk_score(cid, 85.5, "HIGH")
    c = get_candidate(cid)
    assert c["is_live"] is True
    assert c["risk_score"] == 85.5
    assert c["risk_level"] == "HIGH"


def test_get_candidate_returns_none_for_missing_id():
    assert get_candidate(999999) is None


def test_status_change_creates_audit_event():
    cid = insert_candidate("fake-login.com", "realbrand.com")
    update_status(cid, "under_investigation", note="Looks suspicious", actor="analyst1")
    events = get_events(cid)
    assert len(events) == 1
    assert events[0]["event_type"] == "status_change"
    assert events[0]["old_value"] == "new"
    assert events[0]["new_value"] == "under_investigation"


def test_invalid_status_raises_error():
    cid = insert_candidate("fake-login.com", "realbrand.com")
    with pytest.raises(ValueError):
        update_status(cid, "not_a_real_status")


def test_add_note_creates_audit_event_and_appends_text():
    cid = insert_candidate("fake-login.com", "realbrand.com")
    add_note(cid, "First note", actor="analyst1")
    add_note(cid, "Second note", actor="analyst2")
    c = get_candidate(cid)
    events = get_events(cid)
    assert "First note" in c["analyst_notes"]
    assert "Second note" in c["analyst_notes"]
    assert len(events) == 2


def test_get_all_candidates_orders_by_risk_score_desc():
    id_low = insert_candidate("low.com", "brand.com")
    update_risk_score(id_low, 10, "LOW")
    id_high = insert_candidate("high.com", "brand.com")
    update_risk_score(id_high, 90, "HIGH")

    results = get_all_candidates()
    assert results[0]["domain"] == "high.com"
    assert results[1]["domain"] == "low.com"


def test_get_candidates_filters_by_risk_min():
    id_low = insert_candidate("low.com", "brand.com")
    update_risk_score(id_low, 10, "LOW")
    id_high = insert_candidate("high.com", "brand.com")
    update_risk_score(id_high, 90, "HIGH")

    results = get_candidates(risk_min=50)
    assert len(results) == 1
    assert results[0]["domain"] == "high.com"


def test_get_candidates_filters_by_status():
    cid = insert_candidate("test.com", "brand.com")
    update_status(cid, "resolved")
    insert_candidate("other.com", "brand.com")  # stays "new"

    results = get_candidates(status="resolved")
    assert len(results) == 1
    assert results[0]["domain"] == "test.com"


def test_register_and_list_webhooks():
    wh = register_webhook("https://example.com/hook", label="Test", min_risk_level="HIGH")
    assert wh["url"] == "https://example.com/hook"

    webhooks = get_webhooks()
    assert len(webhooks) == 1


def test_delete_webhook():
    wh = register_webhook("https://example.com/hook", min_risk_level="HIGH")
    delete_webhook(wh["id"])
    assert get_webhooks() == []


def test_webhook_threshold_filtering():
    register_webhook("https://example.com/high-only", min_risk_level="HIGH")
    register_webhook("https://example.com/all-levels", min_risk_level="LOW")

    high_matches = get_webhooks_for_risk_level("HIGH")
    low_matches = get_webhooks_for_risk_level("LOW")

    assert len(high_matches) == 2  # both LOW-threshold and HIGH-threshold hooks fire on HIGH
    assert len(low_matches) == 1   # only the LOW-threshold hook fires on LOW


def test_invalid_webhook_risk_level_raises_error():
    with pytest.raises(ValueError):
        register_webhook("https://example.com/hook", min_risk_level="NOT_REAL")
