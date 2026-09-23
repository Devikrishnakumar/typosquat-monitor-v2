"""
main.py
FastAPI application entry point.
Run with: uvicorn api.main:app --reload --port 8000
"""

from fastapi import FastAPI

from src.storage.db import init_db
from api.routes import candidates, webhooks

app = FastAPI(
    title="Typosquat & Brand Impersonation Monitor API",
    description="REST API for querying detected candidates, managing lifecycle, and registering alert webhooks.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "service": "typosquat-monitor-api"}


app.include_router(candidates.router)
app.include_router(webhooks.router)
