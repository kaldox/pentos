"""
Repository – zentrale Datenzugriffsschicht für PentOS.

Bindet an die DB des aktiven Projekts und kapselt sämtliche CRUD-Operationen.
Wichtige Aktionen werden automatisch ins Journal geschrieben.

"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from . import db
from .models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingStatusChange,
    FindingTemplate,
    Host,
    JournalEntry,
    KnowledgeEntry,
    Loot,
    Note,
    RunRecord,
    ScopeEntry,
    Service,
    Severity,
    Task,
    TaskStatus,
    _now,
)


class Repository:
    def __init__(self, db_file: Path):
        db.init_db(db_file)
        self.conn = db.connect(db_file)

    def close(self) -> None:
        self.conn.close()

    # ── Journal ────────────────────────────────────────────────────────────
    def log(self, action: str, detail: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO journal (ts, action, detail) VALUES (?, ?, ?)",
            (_now(), action, detail),
        )
        self.conn.commit()

    def journal(self) -> list[JournalEntry]:
        rows = self.conn.execute("SELECT * FROM journal ORDER BY id").fetchall()
        return [JournalEntry(**dict(r)) for r in rows]

    # ── Hosts ──────────────────────────────────────────────────────────────
    def add_host(self, host: Host) -> Host:
        try:
            cur = self.conn.execute(
                "INSERT INTO hosts (address, hostname, os_guess, status, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (host.address, host.hostname, host.os_guess, host.status, host.notes, host.created_at),
            )
            self.conn.commit()
            host.id = cur.lastrowid
            self.log("Host hinzugefügt", f"{host.address} (id={host.id})")
        except sqlite3.IntegrityError:
            existing = self.get_host_by_address(host.address)
            if existing:
                return existing
            raise
        return host

    def get_host(self, host_id: int) -> Optional[Host]:
        row = self.conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return Host(**dict(row)) if row else None

    def get_host_by_address(self, address: str) -> Optional[Host]:
        row = self.conn.execute("SELECT * FROM hosts WHERE address = ?", (address,)).fetchone()
        return Host(**dict(row)) if row else None

    def list_hosts(self) -> list[Host]:
        rows = self.conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        return [Host(**dict(r)) for r in rows]

    # ── Services ───────────────────────────────────────────────────────────
    def add_service(self, svc: Service) -> Service:
        try:
            cur = self.conn.execute(
                "INSERT INTO services (host_id, port, protocol, name, product, version, extra, tunnel, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (svc.host_id, svc.port, svc.protocol, svc.name, svc.product,
                 svc.version, svc.extra, svc.tunnel, svc.created_at),
            )
            self.conn.commit()
            svc.id = cur.lastrowid
            self.log("Service erkannt", f"{svc.port}/{svc.protocol} {svc.name or ''} (host={svc.host_id})")
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT * FROM services WHERE host_id=? AND port=? AND protocol=?",
                (svc.host_id, svc.port, svc.protocol),
            ).fetchone()
            if row:
                return Service(**dict(row))
            raise
        return svc

    def get_service(self, service_id: int) -> Optional[Service]:
        row = self.conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
        return Service(**dict(row)) if row else None

    def list_services(self, host_id: Optional[int] = None) -> list[Service]:
        if host_id is not None:
            rows = self.conn.execute(
                "SELECT * FROM services WHERE host_id = ? ORDER BY port", (host_id,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM services ORDER BY host_id, port").fetchall()
        return [Service(**dict(r)) for r in rows]

    # ── Findings ───────────────────────────────────────────────────────────
    def add_finding(self, f: Finding) -> Finding:
        cur = self.conn.execute(
            "INSERT INTO findings (title, category, severity, status, description, remediation, "
            "cvss_score, cvss_vector, host_id, service_id, auto, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f.title, f.category.value, f.severity.value, f.status.value, f.description,
             f.remediation, f.cvss_score, f.cvss_vector,
             f.host_id, f.service_id, int(f.auto), f.created_at),
        )
        self.conn.commit()
        f.id = cur.lastrowid
        self._record_status(f.id, None, f.status.value, note="Erstellt")
        tag = "Auto-Finding" if f.auto else "Finding erstellt"
        self.log(tag, f"[{f.severity.value}] {f.title} (id={f.id})")
        return f

    @staticmethod
    def _norm_title(title: str) -> str:
        """Normalisiert einen Finding-Titel für robusten Dedup-Vergleich."""
        return " ".join((title or "").split()).casefold()

    def finding_exists(self, title: str, service_id: Optional[int] = None,
                       host_id: Optional[int] = None) -> bool:
        """Prüft auf ein bereits vorhandenes Finding (normalisierter Titelvergleich).

        Dedup-Schlüssel in Prioritätsreihenfolge:
        - service_id gesetzt -> (Titel, service_id)   [pro Dienst, z.B. nmap-Pipeline]
        - host_id gesetzt    -> (Titel, host_id)       [pro Host, z.B. nxc/enum4linux]
        - sonst              -> (Titel, beide NULL)
        """
        norm = self._norm_title(title)
        if service_id is not None:
            rows = self.conn.execute(
                "SELECT title FROM findings WHERE service_id=?", (service_id,)
            ).fetchall()
        elif host_id is not None:
            rows = self.conn.execute(
                "SELECT title FROM findings WHERE host_id=?", (host_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT title FROM findings WHERE service_id IS NULL AND host_id IS NULL"
            ).fetchall()
        return any(self._norm_title(r["title"]) == norm for r in rows)

    def delete_finding(self, finding_id: int) -> bool:
        # verknüpfte Evidence entkoppeln, statt sie zu löschen
        self.conn.execute(
            "UPDATE evidence SET finding_id = NULL WHERE finding_id = ?", (finding_id,)
        )
        cur = self.conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        self.conn.commit()
        if cur.rowcount:
            self.log("Finding gelöscht", f"id={finding_id}")
        return cur.rowcount > 0

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["auto"] = bool(d["auto"])
        return Finding(**d)

    def list_findings(self) -> list[Finding]:
        rows = self.conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["auto"] = bool(d["auto"])
            out.append(Finding(**d))
        return out

    def set_finding_status(self, finding_id: int, status: str,
                           note: Optional[str] = None) -> bool:
        old = self.conn.execute(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        if old is None:
            return False
        old_status = old["status"]
        cur = self.conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id)
        )
        self.conn.commit()
        if cur.rowcount and status != old_status:
            self._record_status(finding_id, old_status, status, note)
            self.log("Finding-Status geändert",
                     f"id={finding_id} {old_status} -> {status}"
                     + (f" ({note})" if note else ""))
        return cur.rowcount > 0

    def _record_status(self, finding_id: int, old: Optional[str], new: str,
                       note: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO finding_status_history (finding_id, old_status, new_status, note, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (finding_id, old, new, note, _now()),
        )
        self.conn.commit()

    def finding_history(self, finding_id: int) -> list[FindingStatusChange]:
        """Status-Zeitleiste eines Findings (älteste zuerst)."""
        rows = self.conn.execute(
            "SELECT * FROM finding_status_history WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        ).fetchall()
        return [FindingStatusChange(**dict(r)) for r in rows]

    # ── Finding-Templates ──────────────────────────────────────────────────
    @staticmethod
    def _row_to_template(row) -> FindingTemplate:
        d = dict(row)
        d["builtin"] = bool(d["builtin"])
        d["references"] = d.get("references")
        return FindingTemplate(**d)

    def add_template(self, t: FindingTemplate) -> FindingTemplate:
        cur = self.conn.execute(
            'INSERT INTO finding_templates (key, title, category, severity, description, '
            'remediation, cvss_score, cvss_vector, "references", builtin, created_at) '
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (t.key, t.title, t.category.value, t.severity.value, t.description,
             t.remediation, t.cvss_score, t.cvss_vector, t.references,
             int(t.builtin), t.created_at),
        )
        self.conn.commit()
        t.id = cur.lastrowid
        self.log("Template erstellt", f"{t.key} – {t.title}")
        return t

    def list_templates(self) -> list[FindingTemplate]:
        rows = self.conn.execute(
            "SELECT * FROM finding_templates ORDER BY builtin DESC, key"
        ).fetchall()
        return [self._row_to_template(r) for r in rows]

    def get_template(self, ident: str | int) -> Optional[FindingTemplate]:
        """Lookup per ID (int/Ziffern) oder per key (Slug)."""
        if isinstance(ident, int) or (isinstance(ident, str) and ident.isdigit()):
            row = self.conn.execute(
                "SELECT * FROM finding_templates WHERE id = ?", (int(ident),)
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM finding_templates WHERE key = ?", (ident,)
            ).fetchone()
        return self._row_to_template(row) if row else None

    def delete_template(self, ident: str | int) -> bool:
        t = self.get_template(ident)
        if not t:
            return False
        cur = self.conn.execute("DELETE FROM finding_templates WHERE id = ?", (t.id,))
        self.conn.commit()
        if cur.rowcount:
            self.log("Template gelöscht", f"{t.key}")
        return cur.rowcount > 0

    def seed_builtin_templates(self) -> int:
        """Befüllt die Bibliothek aus der kuratierten Wissensbasis (idempotent).

        Bereits vorhandene Keys werden NICHT überschrieben (eigene Edits bleiben).
        Gibt die Anzahl neu angelegter Templates zurück.
        """
        from .knowledge import builtin_templates
        existing = {t.key for t in self.list_templates()}
        added = 0
        for tmpl in builtin_templates():
            if tmpl.key not in existing:
                self.add_template(tmpl)
                added += 1
        return added

    def instantiate_template(self, ident: str | int, host_id: Optional[int] = None,
                             service_id: Optional[int] = None,
                             title_suffix: str = "") -> Optional[Finding]:
        """Erzeugt aus einer Vorlage ein konkretes Finding im Projekt."""
        t = self.get_template(ident)
        if not t:
            return None
        title = t.title + (f" {title_suffix}" if title_suffix else "")
        f = Finding(
            title=title, category=t.category, severity=t.severity,
            description=t.description, remediation=t.remediation,
            cvss_score=t.cvss_score, cvss_vector=t.cvss_vector,
            host_id=host_id, service_id=service_id, auto=False,
        )
        return self.add_finding(f)


    def add_task(self, t: Task, dedup: bool = True) -> Optional[Task]:
        if dedup:
            if t.dedup_scope == "host" and t.host_id is not None:
                row = self.conn.execute(
                    "SELECT 1 FROM tasks WHERE title=? AND host_id=?", (t.title, t.host_id)
                ).fetchone()
                if row:
                    return None
            elif t.service_id is not None:
                row = self.conn.execute(
                    "SELECT 1 FROM tasks WHERE title=? AND service_id=?", (t.title, t.service_id)
                ).fetchone()
                if row:
                    return None
        cur = self.conn.execute(
            "INSERT INTO tasks (title, status, source, host_id, service_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (t.title, t.status.value, t.source, t.host_id, t.service_id, t.created_at),
        )
        self.conn.commit()
        t.id = cur.lastrowid
        return t

    def list_tasks(self, status: Optional[TaskStatus] = None) -> list[Task]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE status = ? ORDER BY id", (status.value,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM tasks ORDER BY id").fetchall()
        return [Task(**dict(r)) for r in rows]

    def set_task_status(self, task_id: int, status: TaskStatus) -> bool:
        cur = self.conn.execute(
            "UPDATE tasks SET status = ? WHERE id = ?", (status.value, task_id)
        )
        self.conn.commit()
        if cur.rowcount:
            self.log("Task-Status geändert", f"id={task_id} -> {status.value}")
        return cur.rowcount > 0

    # ── Notes ──────────────────────────────────────────────────────────────
    def add_note(self, n: Note) -> Note:
        cur = self.conn.execute(
            "INSERT INTO notes (title, body, category, host_id, service_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (n.title, n.body, n.category, n.host_id, n.service_id, n.created_at),
        )
        self.conn.commit()
        n.id = cur.lastrowid
        self.log("Notiz angelegt", f"{n.title} (id={n.id})")
        return n

    def list_notes(self) -> list[Note]:
        rows = self.conn.execute("SELECT * FROM notes ORDER BY id").fetchall()
        return [Note(**dict(r)) for r in rows]

    def get_note(self, note_id: int) -> Optional[Note]:
        row = self.conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        return Note(**dict(row)) if row else None

    def delete_note(self, note_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        self.conn.commit()
        if cur.rowcount:
            self.log("Notiz gelöscht", f"id={note_id}")
        return cur.rowcount > 0

    # ── Loot ───────────────────────────────────────────────────────────────
    def add_loot(self, l: Loot) -> Loot:
        cur = self.conn.execute(
            "INSERT INTO loot (type, label, value, host_id, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (l.type.value, l.label, l.value, l.host_id, l.source, l.created_at),
        )
        self.conn.commit()
        l.id = cur.lastrowid
        self.log("Loot gespeichert", f"[{l.type.value}] {l.label} (id={l.id})")
        return l

    def list_loot(self) -> list[Loot]:
        rows = self.conn.execute("SELECT * FROM loot ORDER BY id").fetchall()
        return [Loot(**dict(r)) for r in rows]

    def delete_loot(self, loot_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM loot WHERE id = ?", (loot_id,))
        self.conn.commit()
        if cur.rowcount:
            self.log("Loot gelöscht", f"id={loot_id}")
        return cur.rowcount > 0

    # ── Evidence ───────────────────────────────────────────────────────────
    def add_evidence(self, e: Evidence) -> Evidence:
        cur = self.conn.execute(
            "INSERT INTO evidence (kind, path, description, finding_id, host_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (e.kind, e.path, e.description, e.finding_id, e.host_id, e.created_at),
        )
        self.conn.commit()
        e.id = cur.lastrowid
        self.log("Evidence hinzugefügt", f"{e.kind}: {e.path} (id={e.id})")
        return e

    def list_evidence(self) -> list[Evidence]:
        rows = self.conn.execute("SELECT * FROM evidence ORDER BY id").fetchall()
        return [Evidence(**dict(r)) for r in rows]

    def delete_evidence(self, evidence_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        self.conn.commit()
        if cur.rowcount:
            self.log("Evidence gelöscht", f"id={evidence_id}")
        return cur.rowcount > 0

    # ── Knowledge ──────────────────────────────────────────────────────────
    def add_knowledge(self, k: KnowledgeEntry) -> KnowledgeEntry:
        cur = self.conn.execute(
            "INSERT INTO knowledge (tag, title, body, created_at) VALUES (?, ?, ?, ?)",
            (k.tag, k.title, k.body, k.created_at),
        )
        self.conn.commit()
        k.id = cur.lastrowid
        self.log("Wissens-Eintrag", f"[{k.tag}] {k.title} (id={k.id})")
        return k

    def list_knowledge(self, tag: Optional[str] = None) -> list[KnowledgeEntry]:
        if tag:
            rows = self.conn.execute(
                "SELECT * FROM knowledge WHERE tag = ? ORDER BY id", (tag,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM knowledge ORDER BY tag, id").fetchall()
        return [KnowledgeEntry(**dict(r)) for r in rows]

    # ── Scope ──────────────────────────────────────────────────────────────
    def add_scope(self, value: str, kind: str = "host") -> ScopeEntry:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO scope (value, kind, created_at) VALUES (?, ?, ?)",
            (value, kind, _now()),
        )
        self.conn.commit()
        if cur.lastrowid:
            self.log("Scope erweitert", f"{kind}: {value}")
        row = self.conn.execute("SELECT * FROM scope WHERE value = ?", (value,)).fetchone()
        return ScopeEntry(**dict(row))

    def list_scope(self) -> list[ScopeEntry]:
        rows = self.conn.execute("SELECT * FROM scope ORDER BY id").fetchall()
        return [ScopeEntry(**dict(r)) for r in rows]

    def remove_scope(self, scope_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM scope WHERE id = ?", (scope_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def in_scope(self, host: str) -> bool:
        """True, wenn host im Scope liegt ODER kein Scope definiert ist."""
        import ipaddress

        entries = self.list_scope()
        if not entries:
            return True  # kein Scope gesetzt -> keine Einschränkung (CTF-freundlich)
        for e in entries:
            if e.kind == "host" and e.value.lower() == host.lower():
                return True
            if e.kind == "cidr":
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(e.value, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def scope_defined(self) -> bool:
        return len(self.list_scope()) > 0

    # ── Runs ───────────────────────────────────────────────────────────────
    def add_run(self, r: RunRecord) -> RunRecord:
        cur = self.conn.execute(
            "INSERT INTO runs (tool, target, command, returncode, output_path, duration_ms, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (r.tool, r.target, r.command, r.returncode, r.output_path, r.duration_ms, r.started_at),
        )
        self.conn.commit()
        r.id = cur.lastrowid
        self.log("Tool ausgeführt", f"{r.tool} -> {r.target} (rc={r.returncode})")
        return r

    def list_runs(self) -> list[RunRecord]:
        rows = self.conn.execute("SELECT * FROM runs ORDER BY id").fetchall()
        return [RunRecord(**dict(r)) for r in rows]

    # ── Playbook-Fortschritt ─────────────────────────────────────────────────
    def set_playbook_step(self, playbook: str, step_id: str,
                          status: str = "done", note: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO playbook_progress (playbook, step_id, status, note, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(playbook, step_id) DO UPDATE SET status=excluded.status, "
            "note=excluded.note, updated_at=excluded.updated_at",
            (playbook, step_id, status, note, _now()),
        )
        self.conn.commit()
        self.log("Playbook-Schritt", f"{playbook}/{step_id} -> {status}")

    def unset_playbook_step(self, playbook: str, step_id: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM playbook_progress WHERE playbook=? AND step_id=?", (playbook, step_id)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def playbook_progress(self, playbook: str) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT step_id, status, note FROM playbook_progress WHERE playbook=?", (playbook,)
        ).fetchall()
        return {r["step_id"]: {"status": r["status"], "note": r["note"]} for r in rows}

    # ── RAG-Index (Vektor-Suche über Projektdaten) ───────────────────────────
    def rag_clear(self) -> None:
        self.conn.execute("DELETE FROM rag_index")
        self.conn.commit()

    def rag_add(self, doc_type: str, doc_id: Optional[int], title: Optional[str],
                chunk: str, embedding_json: str) -> None:
        self.conn.execute(
            "INSERT INTO rag_index (doc_type, doc_id, title, chunk, embedding, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (doc_type, doc_id, title, chunk, embedding_json, _now()),
        )
        self.conn.commit()

    def rag_all(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc_type, doc_id, title, chunk, embedding FROM rag_index"
        ).fetchall()
        return [dict(r) for r in rows]

    def rag_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM rag_index").fetchone()["n"]
