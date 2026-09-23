"""
candidates.py
GET /api/candidates - filtered list
GET /api/candidates/{id} - single candidate detail
GET /api/candidates/{id}/events - audit trail
POST /api/candidates/{id}/status - update lifecycle status
POST /api/candidates/{id}/takedown - generate takedown report
"""

from typing import Optional

from fastapi import APIRouter, HTTPException

from src.storage.db import (
    get_candidates, get_candidate, get_events, update_status,
)
from src.enrichment.whois_lookup import get_whois_info
from src.reporting.report_generator import generate_report
from api.schemas import StatusUpdateRequest, TakedownResponse

router = APIRouter(prefix="/api/candidates", tags=["candidates"])


@router.get("")
def list_candidates(
    risk_min: Optional[float] = None,
    brand: Optional[str] = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    return get_candidates(
        risk_min=risk_min, brand=brand, status=status, risk_level=risk_level,
        since=since, until=until, limit=limit, offset=offset,
    )


@router.get("/{candidate_id}")
def get_one(candidate_id: int):
    c = get_candidate(candidate_id)
    if c is None:
        raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
    return c


@router.get("/{candidate_id}/events")
def get_candidate_events(candidate_id: int):
    c = get_candidate(candidate_id)
    if c is None:
        raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
    return get_events(candidate_id)


@router.post("/{candidate_id}/status")
def set_status(candidate_id: int, body: StatusUpdateRequest):
    try:
        return update_status(candidate_id, body.status, note=body.note, actor=body.actor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{candidate_id}/takedown", response_model=TakedownResponse)
def trigger_takedown(candidate_id: int):
    candidate = get_candidate(candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")

    whois_info = get_whois_info(candidate["domain"])
    report_path = generate_report(candidate, whois_info)

    return TakedownResponse(
        candidate_id=candidate_id,
        domain=candidate["domain"],
        report_path=report_path,
    )
