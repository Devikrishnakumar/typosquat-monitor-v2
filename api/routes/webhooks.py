"""
webhooks.py
GET /api/webhooks - list registered webhooks
POST /api/webhooks - register a new webhook
DELETE /api/webhooks/{id} - remove a webhook
"""

from fastapi import APIRouter, HTTPException

from src.storage.db import register_webhook, get_webhooks, delete_webhook
from api.schemas import WebhookRegisterRequest, WebhookOut

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


@router.get("")
def list_webhooks():
    return get_webhooks()


@router.post("", response_model=WebhookOut)
def create_webhook(body: WebhookRegisterRequest):
    try:
        return register_webhook(str(body.url), label=body.label, min_risk_level=body.min_risk_level)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{webhook_id}")
def remove_webhook(webhook_id: int):
    try:
        delete_webhook(webhook_id)
        return {"deleted": webhook_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
