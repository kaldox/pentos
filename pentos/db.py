"""
SQLite-Anbindung und Schema für PentOS.

Pro Projekt existiert eine eigene DB unter <projekt>/database/pentos.db.

"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,
    hostname TEXT,
    os_guess TEXT,
    status TEXT DEFAULT 'up',
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    name TEXT,
    product TEXT,
    version TEXT,
    extra TEXT,
    tunnel TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(host_id, port, protocol),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    status TEXT,
    description TEXT,
    host_id INTEGER,
    service_id INTEGER,
    auto INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT,
    source TEXT,
    host_id INTEGER,
    service_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT,
    category TEXT,
    host_id INTEGER,
    service_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    label TEXT NOT NULL,
    value TEXT,
    host_id INTEGER,
    source TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,
    path TEXT NOT NULL,
    description TEXT,
    finding_id INTEGER,
    host_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL UNIQUE,
    kind TEXT DEFAULT 'host',          -- host | cidr
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    target TEXT,
    command TEXT,
    returncode INTEGER,
    output_path TEXT,
    duration_ms INTEGER,
    started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS playbook_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT DEFAULT 'done',        -- done | skip
    note TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(playbook, step_id)
);

CREATE TABLE IF NOT EXISTS finding_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    description TEXT,
    remediation TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    "references" TEXT,
    builtin INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rag_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_type TEXT NOT NULL,            -- finding | note | knowledge | loot | host | service
    doc_id INTEGER,
    title TEXT,
    chunk TEXT NOT NULL,
    embedding TEXT NOT NULL,           -- JSON-Liste (Vektor)
    updated_at TEXT NOT NULL
);
"""


def connect(db_file: Path) -> sqlite3.Connection:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Fügt neue Spalten zu bestehenden Tabellen hinzu (vorwärtskompatibel)."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
    for col, decl in (("remediation", "TEXT"), ("cvss_score", "REAL"), ("cvss_vector", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
    conn.commit()


def init_db(db_file: Path) -> None:
    conn = connect(db_file)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate(conn)
    finally:
        conn.close()
