"""
schemas.py
Pydantic models for API request/response validation.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, HttpUrl


class CandidateOut(BaseModel):
    id: int
    domain: str
    decoded_domain: Optional[str] = None
    matched_brand: str
    detected_at: str
    is_live: Optional[bool] = None
    visual_similarity: Optional[float] = None
    ssim_similarity: Optional[float] = None
    combined_similarity: Optional[float] = None
    has_login_form: Optional[bool] = None
    has_mx: Optional[bool] = None
    has_spf: Optional[bool] = None
    has_dmarc: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    ssl_san_count: Optional[int] = None
    ssl_validity_days: Optional[int] = None
    ssl_is_free_or_short_lived: Optional[bool] = None
    favicon_hash: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    screenshot_path: Optional[str] = None
    status: str
    analyst_notes: Optional[str] = None
    status_changed_at: Optional[datetime] = None
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class StatusUpdateRequest(BaseModel):
    status: str
    note: Optional[str] = None
    actor: str = "api"


class TakedownResponse(BaseModel):
    candidate_id: int
    domain: str
    report_path: str


class WebhookRegisterRequest(BaseModel):
    url: HttpUrl
    label: Optional[str] = None
    min_risk_level: str = "HIGH"  # only fire for candidates at/above this level


class WebhookOut(BaseModel):
    id: int
    url: str
    label: Optional[str] = None
    min_risk_level: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
