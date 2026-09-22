"""
db.py
Storage API on top of SQLAlchemy. Same function names as the old SQLite version,
plus lifecycle (status/notes/audit), Phase 3 enrichment updates, and filtered queries.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from .database import SessionLocal, DATABASE_URL, PROJECT_ROOT
from .models import Candidate, CandidateEvent, STATUSES

DB_PATH = DATABASE_URL  # kept for backward compatibility


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Bring the database schema up to date using Alembic migrations."""
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    command.upgrade(cfg, "head")


# ---------- writes used by the pipeline (unchanged signatures) ----------

def insert_candidate(domain, matched_brand, decoded_domain=None):
    with session_scope() as s:
        c = Candidate(domain=domain, matched_brand=matched_brand, decoded_domain=decoded_domain)
        s.add(c)
        s.flush()
        return c.id


def _update(candidate_id, **fields):
    with session_scope() as s:
        c = s.get(Candidate, candidate_id)
        if c is None:
            raise ValueError(f"Candidate {candidate_id} not found")
        for k, v in fields.items():
            setattr(c, k, v)


def update_liveness(candidate_id, is_live):
    _update(candidate_id, is_live=bool(is_live))


def update_screenshot_path(candidate_id, path):
    _update(candidate_id, screenshot_path=path)


def update_visual_similarity(candidate_id, score):
    _update(candidate_id, visual_similarity=score)


def update_content_signals(candidate_id, has_login_form):
    _update(candidate_id, has_login_form=bool(has_login_form))


def update_risk_score(candidate_id, score, level):
    _update(candidate_id, risk_score=score, risk_level=level)


# ---------- Phase 3: extended enrichment signals ----------

def update_email_security(candidate_id, has_mx, has_spf, has_dmarc):
    _update(candidate_id, has_mx=has_mx, has_spf=has_spf, has_dmarc=has_dmarc)


def update_ssl_metadata(candidate_id, ssl_info):
    if not ssl_info:
        return
    _update(
        candidate_id,
        ssl_issuer=ssl_info.get("issuer"),
        ssl_san_count=ssl_info.get("san_count"),
        ssl_validity_days=ssl_info.get("validity_days"),
        ssl_is_free_or_short_lived=ssl_info.get("is_free_or_short_lived"),
    )


def update_favicon_hash(candidate_id, favicon_hash):
    _update(candidate_id, favicon_hash=str(favicon_hash) if favicon_hash is not None else None)


# ---------- lifecycle ----------

def update_status(candidate_id, new_status, note=None, actor="analyst"):
    if new_status not in STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {STATUSES}")
    with session_scope() as s:
        c = s.get(Candidate, candidate_id)
        if c is None:
            raise ValueError(f"Candidate {candidate_id} not found")
        old = c.status
        c.status = new_status
        c.status_changed_at = datetime.now(timezone.utc)
        s.add(CandidateEvent(candidate_id=c.id, event_type="status_change",
                             old_value=old, new_value=new_status, note=note, actor=actor))
        return c.to_dict()


def add_note(candidate_id, note, actor="analyst"):
    with session_scope() as s:
        c = s.get(Candidate, candidate_id)
        if c is None:
            raise ValueError(f"Candidate {candidate_id} not found")
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        line = f"[{stamp}] {actor}: {note}"
        c.analyst_notes = f"{c.analyst_notes}\n{line}" if c.analyst_notes else line
        s.add(CandidateEvent(candidate_id=c.id, event_type="note", note=note, actor=actor))
        return c.to_dict()


def get_events(candidate_id):
    with session_scope() as s:
        rows = s.scalars(
            select(CandidateEvent).where(CandidateEvent.candidate_id == candidate_id)
            .order_by(CandidateEvent.created_at)
        ).all()
        return [{col.name: getattr(r, col.name) for col in r.__table__.columns} for r in rows]


# ---------- reads ----------

def get_candidate(candidate_id):
    with session_scope() as s:
        c = s.get(Candidate, candidate_id)
        return c.to_dict() if c else None


def get_all_candidates():
    with session_scope() as s:
        rows = s.scalars(
            select(Candidate).order_by(Candidate.risk_score.desc().nulls_last(),
                                       Candidate.detected_at.desc())
        ).all()
        return [r.to_dict() for r in rows]


def get_candidates(risk_min=None, brand=None, status=None, risk_level=None,
                   since=None, until=None, limit=100, offset=0):
    """Filtered query. since/until are ISO date strings, e.g. '2026-09-01'."""
    stmt = select(Candidate)
    if risk_min is not None:
        stmt = stmt.where(Candidate.risk_score >= risk_min)
    if brand:
        stmt = stmt.where(Candidate.matched_brand == brand)
    if status:
        stmt = stmt.where(Candidate.status == status)
    if risk_level:
        stmt = stmt.where(Candidate.risk_level == risk_level)
    if since:
        stmt = stmt.where(Candidate.detected_at >= since)
    if until:
        stmt = stmt.where(Candidate.detected_at <= until)
    stmt = stmt.order_by(Candidate.risk_score.desc().nulls_last(),
                         Candidate.detected_at.desc()).limit(limit).offset(offset)
    with session_scope() as s:
        return [r.to_dict() for r in s.scalars(stmt).all()]


if __name__ == "__main__":
    # Smoke test
    init_db()
    cid = insert_candidate("paypa1-test.com", "paypal.com")
    update_liveness(cid, True)
    update_risk_score(cid, 87, "HIGH")
    update_email_security(cid, True, True, False)
    update_favicon_hash(cid, 123456789)
    update_status(cid, "under_investigation", note="Login page resembles PayPal")
    add_note(cid, "Requested registrar contact")
    print(get_candidate(cid))
    print("events:", get_events(cid))
    print("filtered:", len(get_candidates(risk_min=70, status="under_investigation")))
    with session_scope() as s:            # clean up the test row
        s.delete(s.get(Candidate, cid))
    print("Database OK:", DATABASE_URL)
