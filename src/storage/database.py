"""
database.py
Engine + session factory. Reads DATABASE_URL from the environment.
Default: SQLite at data/monitor.db.
PostgreSQL later: set DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/typosquat
"""

import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
(PROJECT_ROOT / "data").mkdir(exist_ok=True)

DEFAULT_URL = f"sqlite:///{(PROJECT_ROOT / 'data' / 'monitor.db').as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_URL)
IS_SQLITE = DATABASE_URL.startswith("sqlite")


class Base(DeclarativeBase):
    pass


if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")   # readers don't block writers
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()
else:
    engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
