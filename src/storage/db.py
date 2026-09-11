"""
db.py
SQLite storage for detected typosquat candidates.
"""

import sqlite3
from datetime import datetime, timezone

DB_PATH = "data/monitor.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            decoded_domain TEXT DEFAULT NULL,
            matched_brand TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            is_live INTEGER DEFAULT NULL,
            visual_similarity REAL DEFAULT NULL,
            has_login_form INTEGER DEFAULT NULL,
            risk_score REAL DEFAULT NULL,
            risk_level TEXT DEFAULT NULL,
            screenshot_path TEXT DEFAULT NULL,
            status TEXT DEFAULT 'new'
        )
    """)
    conn.commit()
    conn.close()


def insert_candidate(domain, matched_brand, decoded_domain=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO candidates (domain, decoded_domain, matched_brand, detected_at)
        VALUES (?, ?, ?, ?)
    """, (domain, decoded_domain, matched_brand, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    candidate_id = cursor.lastrowid
    conn.close()
    return candidate_id


def update_liveness(candidate_id, is_live):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET is_live = ? WHERE id = ?", (1 if is_live else 0, candidate_id))
    conn.commit()
    conn.close()


def update_screenshot_path(candidate_id, path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET screenshot_path = ? WHERE id = ?", (path, candidate_id))
    conn.commit()
    conn.close()


def update_visual_similarity(candidate_id, score):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET visual_similarity = ? WHERE id = ?", (score, candidate_id))
    conn.commit()
    conn.close()


def update_content_signals(candidate_id, has_login_form):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET has_login_form = ? WHERE id = ?", (1 if has_login_form else 0, candidate_id))
    conn.commit()
    conn.close()


def update_risk_score(candidate_id, score, level):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE candidates SET risk_score = ?, risk_level = ? WHERE id = ?", (score, level, candidate_id))
    conn.commit()
    conn.close()


def get_all_candidates():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM candidates ORDER BY risk_score DESC, detected_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
