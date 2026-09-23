"""
test_api.py
Tests for the FastAPI REST endpoints.
"""

from src.storage.db import insert_candidate, update_risk_score


def test_root_endpoint(api_client):
    resp = api_client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_list_candidates_empty(api_client):
    resp = api_client.get("/api/candidates")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_candidates_returns_inserted_row(api_client):
    insert_candidate("fake.com", "brand.com")
    resp = api_client.get("/api/candidates")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["domain"] == "fake.com"


def test_get_single_candidate(api_client):
    cid = insert_candidate("fake.com", "brand.com")
    resp = api_client.get(f"/api/candidates/{cid}")
    assert resp.status_code == 200
    assert resp.json()["domain"] == "fake.com"


def test_get_single_candidate_404_for_missing(api_client):
    resp = api_client.get("/api/candidates/999999")
    assert resp.status_code == 404


def test_filter_by_risk_level(api_client):
    id_low = insert_candidate("low.com", "brand.com")
    update_risk_score(id_low, 10, "LOW")
    id_high = insert_candidate("high.com", "brand.com")
    update_risk_score(id_high, 90, "HIGH")

    resp = api_client.get("/api/candidates?risk_level=HIGH")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["domain"] == "high.com"


def test_update_status_via_api(api_client):
    cid = insert_candidate("fake.com", "brand.com")
    resp = api_client.post(
        f"/api/candidates/{cid}/status",
        json={"status": "under_investigation", "note": "test note", "actor": "tester"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "under_investigation"


def test_update_status_invalid_returns_400(api_client):
    cid = insert_candidate("fake.com", "brand.com")
    resp = api_client.post(
        f"/api/candidates/{cid}/status",
        json={"status": "not_a_real_status"},
    )
    assert resp.status_code == 400


def test_register_and_list_webhooks_via_api(api_client):
    resp = api_client.post(
        "/api/webhooks",
        json={"url": "https://example.com/hook", "label": "Test", "min_risk_level": "HIGH"},
    )
    assert resp.status_code == 200
    webhook_id = resp.json()["id"]

    resp = api_client.get("/api/webhooks")
    assert len(resp.json()) == 1

    resp = api_client.delete(f"/api/webhooks/{webhook_id}")
    assert resp.status_code == 200

    resp = api_client.get("/api/webhooks")
    assert len(resp.json()) == 0


def test_invalid_webhook_url_returns_422(api_client):
    resp = api_client.post(
        "/api/webhooks",
        json={"url": "not-a-valid-url", "min_risk_level": "HIGH"},
    )
    assert resp.status_code == 422
