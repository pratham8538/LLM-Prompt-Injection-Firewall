"""
Security event logging + settings storage — Stage 5
======================================================

Uses SQLite for zero-infra persistence (swap for Postgres/MySQL later by
replacing this module's connection logic — the call sites in api.py don't
need to change).

Tables:
  events    — one row per analyzed request (Stage 5)
  settings  — single-row table holding admin-configurable thresholds (Stage 6)

Privacy (per project blueprint §21): we do NOT store the raw prompt by
default. We store a short, non-reversible preview (first 80 chars) plus
a SHA-256 fingerprint, which is enough for the dashboard/audit trail
without retaining full user content. This is a policy choice — see
STORE_FULL_PROMPT below to change it for a controlled/local deployment.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager

DB_PATH = "firewall.db"

# Privacy knob: if False (default), only a short preview + hash is stored,
# never the full prompt. Flip to True only if you have a specific reason
# (e.g. a local single-user dev deployment) — see doc §21.
STORE_FULL_PROMPT = False

DEFAULT_THRESHOLDS = {"LOW": [0, 39], "MEDIUM": [40, 69], "HIGH": [70, 100]}

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                application_id TEXT,
                prompt_preview TEXT,
                prompt_hash TEXT,
                prompt_full TEXT,
                threat_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                action TEXT NOT NULL,
                detections TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                review_label TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                thresholds TEXT NOT NULL,
                rule_weights TEXT
            )
            """
        )
        # Migration for DBs created before rule_weights existed.
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(settings)").fetchall()]
        if "rule_weights" not in cols:
            conn.execute("ALTER TABLE settings ADD COLUMN rule_weights TEXT")
        existing = conn.execute("SELECT id FROM settings WHERE id = 1").fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO settings (id, thresholds, rule_weights) VALUES (1, ?, NULL)",
                (json.dumps(DEFAULT_THRESHOLDS),),
            )


def log_event(
    *,
    prompt: str,
    threat_score: int,
    risk_level: str,
    action: str,
    detections: list[str],
    endpoint: str,
    application_id: str | None = None,
) -> str:
    event_id = str(uuid.uuid4())
    preview = prompt[:80] + ("..." if len(prompt) > 80 else "")
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (id, timestamp, application_id, prompt_preview, prompt_hash,
                 prompt_full, threat_score, risk_level, action, detections, endpoint, review_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                event_id,
                time.time(),
                application_id,
                preview,
                prompt_hash,
                prompt if STORE_FULL_PROMPT else None,
                threat_score,
                risk_level,
                action,
                json.dumps(detections),
                endpoint,
            ),
        )
    return event_id


def get_events(limit: int = 50, offset: int = 0) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def _row_to_event(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "application_id": row["application_id"],
        "prompt_preview": row["prompt_preview"],
        "prompt_hash": row["prompt_hash"],
        "threat_score": row["threat_score"],
        "risk_level": row["risk_level"],
        "action": row["action"],
        "detections": json.loads(row["detections"]),
        "endpoint": row["endpoint"],
        "review_label": row["review_label"],
    }


def get_statistics() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM events GROUP BY action"
        ).fetchall()
        avg_score_row = conn.execute("SELECT AVG(threat_score) a FROM events").fetchone()
        detection_rows = conn.execute("SELECT detections FROM events").fetchall()

    action_counts = {"ALLOW": 0, "WARN": 0, "BLOCK": 0}
    for r in by_action:
        action_counts[r["action"]] = r["c"]

    category_counts: dict[str, int] = {}
    for r in detection_rows:
        for cat in json.loads(r["detections"]):
            category_counts[cat] = category_counts.get(cat, 0) + 1
    top_attacks = sorted(category_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]

    return {
        "total_requests": total,
        "allowed": action_counts["ALLOW"],
        "warned": action_counts["WARN"],
        "blocked": action_counts["BLOCK"],
        "average_threat_score": round(avg_score_row["a"] or 0, 1),
        "top_detected_attacks": [{"category": c, "count": n} for c, n in top_attacks],
    }


def get_settings() -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT thresholds FROM settings WHERE id = 1").fetchone()
    return json.loads(row["thresholds"])


def update_settings(thresholds: dict) -> dict:
    with get_conn() as conn:
        conn.execute(
            "UPDATE settings SET thresholds = ? WHERE id = 1",
            (json.dumps(thresholds),),
        )
    return thresholds


def get_rule_weights() -> dict | None:
    """Returns admin-applied weight overrides, or None if learning mode
    hasn't been applied yet (detector.py's built-in defaults are used)."""
    with get_conn() as conn:
        row = conn.execute("SELECT rule_weights FROM settings WHERE id = 1").fetchone()
    raw = row["rule_weights"]
    return json.loads(raw) if raw else None


def update_rule_weights(weights: dict) -> dict:
    with get_conn() as conn:
        conn.execute(
            "UPDATE settings SET rule_weights = ? WHERE id = 1",
            (json.dumps(weights),),
        )
    return weights


def get_review_insights() -> dict:
    """Aggregate reviewed events by detection category: how often each
    category showed up on something an admin later marked 'legitimate'
    (false positive) vs 'actual_attack' (confirmed). This is the raw
    material for Stage 7's learning mode — see api.py for how it turns
    into a weight suggestion."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT detections, review_label FROM events WHERE review_label IS NOT NULL"
        ).fetchall()

    tally: dict[str, dict[str, int]] = {}
    for r in rows:
        label = r["review_label"]
        for cat in json.loads(r["detections"]):
            if cat.startswith("decoded:"):
                continue  # sub-detections from decoded payloads aren't a rule category
            bucket = tally.setdefault(cat, {"legitimate": 0, "actual_attack": 0})
            bucket[label] = bucket.get(label, 0) + 1
    return tally


def set_review_label(event_id: str, label: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE events SET review_label = ? WHERE id = ?", (label, event_id)
        )
    return cur.rowcount > 0
