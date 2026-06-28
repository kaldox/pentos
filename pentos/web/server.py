"""
Web-Dashboard-Backend für PentOS (optional, `pip install -e ".[web]"`).

Schlankes FastAPI-Backend, das aus dem bestehenden Repository/SQLite liest und
eine JSON-API plus das statische Single-Page-Frontend ausliefert. Bindet per
Default an 127.0.0.1 (nur lokal erreichbar) – minimale Angriffsfläche, passend
zur Local-First-Idee.

Lesend (read-only) in dieser Phase. Interaktive Schreibaktionen kommen später.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .. import config
from ..models import SEVERITY_ORDER, Severity
from ..repository import Repository
from ..workspace import list_projects

# Auf Modulebene, damit FastAPI die (durch `from __future__ import annotations`
# verstringten) Typ-Hints der Endpunkte auflösen kann. Optional – None ohne fastapi.
try:
    from fastapi import Request, Body
except ModuleNotFoundError:  # pragma: no cover
    Request = Body = None

STATIC_DIR = Path(__file__).parent / "static"


def _repo(project: str) -> Repository:
    return Repository(config.db_path(project))


def _finding_dict(f) -> dict:
    return {
        "id": f.id, "title": f.title, "severity": f.severity.value,
        "category": f.category.value, "status": f.status.value,
        "description": f.description, "remediation": f.remediation,
        "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
        "host_id": f.host_id, "service_id": f.service_id, "auto": f.auto,
    }


def create_app(project: Optional[str] = None, _bind_host: str = "127.0.0.1",
               _bind_port: int = 8787):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise SystemExit(
            "FastAPI fehlt. Installiere die Web-Extras: pip install -e \".[web]\""
        ) from exc

    app = FastAPI(title="PentOS Dashboard", docs_url="/api/docs")

    # Erlaubte Origins für Schreibzugriffe = die eigene Bind-Adresse.
    # Schützt das lokale Dashboard vor Drive-By-Schreibzugriffen fremder Websites.
    _allowed_origins = {
        f"http://127.0.0.1:{_bind_port}", f"http://localhost:{_bind_port}",
        f"http://{_bind_host}:{_bind_port}",
    }

    def _guard_write(request: Request):
        origin = request.headers.get("origin")
        if origin and origin not in _allowed_origins:
            raise HTTPException(403, "Schreibzugriff nur vom lokalen Dashboard erlaubt.")

    _VALID_STATUS = {s.value for s in __import__("pentos.models", fromlist=["FindingStatus"]).FindingStatus}

    def resolve(name: Optional[str]) -> str:
        name = name or project
        if not name:
            projects = list_projects()
            if not projects:
                raise HTTPException(404, "Kein Projekt vorhanden.")
            name = projects[0]
        if name not in list_projects():
            raise HTTPException(404, f"Projekt '{name}' nicht gefunden.")
        return name

    # ── API ────────────────────────────────────────────────────────────────
    @app.get("/api/projects")
    def api_projects():
        return {"projects": list_projects(), "active": project}

    @app.get("/api/project/{name}/summary")
    def api_summary(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            findings = repo.list_findings()
            hosts = repo.list_hosts()
            services = repo.list_services()
            loot = repo.list_loot()
            tasks = repo.list_tasks()
            sev = {s.value: 0 for s in Severity}
            for f in findings:
                sev[f.severity.value] += 1
            done = sum(1 for t in tasks if t.status.value == "done")
            journal = repo.journal()[-12:][::-1]
            return {
                "project": name,
                "counts": {
                    "hosts": len(hosts), "services": len(services),
                    "findings": len(findings), "loot": len(loot),
                    "tasks_total": len(tasks), "tasks_done": done,
                },
                "severity": sev,
                "activity": [
                    {"action": j.action, "detail": j.detail, "at": j.ts}
                    for j in journal
                ],
            }
        finally:
            repo.close()

    @app.get("/api/project/{name}/findings")
    def api_findings(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            findings = sorted(repo.list_findings(),
                              key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
            return {"findings": [_finding_dict(f) for f in findings]}
        finally:
            repo.close()

    @app.get("/api/project/{name}/hosts")
    def api_hosts(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            services = repo.list_services()
            out = []
            for h in repo.list_hosts():
                svcs = [s for s in services if s.host_id == h.id]
                out.append({
                    "id": h.id, "address": h.address, "hostname": h.hostname,
                    "os_guess": h.os_guess, "status": h.status,
                    "services": [{
                        "port": s.port, "protocol": s.protocol, "name": s.name,
                        "product": s.product, "version": s.version,
                    } for s in sorted(svcs, key=lambda s: s.port or 0)],
                })
            return {"hosts": out}
        finally:
            repo.close()

    @app.get("/api/project/{name}/loot")
    def api_loot(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            return {"loot": [{
                "id": l.id, "type": l.type.value if hasattr(l.type, "value") else l.type,
                "label": l.label, "value": l.value, "host_id": l.host_id,
                "source": l.source,
            } for l in repo.list_loot()]}
        finally:
            repo.close()

    @app.get("/api/project/{name}/notes")
    def api_notes(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            return {"notes": [{
                "id": n.id, "title": n.title, "category": n.category,
                "body": n.body, "created_at": n.created_at,
            } for n in repo.list_notes()]}
        finally:
            repo.close()

    # ── Schreibaktionen (interaktiv) ─────────────────────────────────────────
    @app.get("/api/project/{name}/finding/{fid}")
    def api_finding_detail(name: str, fid: int):
        name = resolve(name)
        repo = _repo(name)
        try:
            f = repo.get_finding(fid)
            if not f:
                raise HTTPException(404, f"Finding {fid} nicht gefunden.")
            d = _finding_dict(f)
            d["created_at"] = f.created_at
            # Verortung
            loc = None
            if f.service_id:
                s = repo.get_service(f.service_id)
                if s:
                    h = repo.get_host(s.host_id)
                    loc = f"{h.address if h else ''}:{s.port}/{s.protocol}"
            elif f.host_id:
                h = repo.get_host(f.host_id)
                loc = h.address if h else None
            d["location"] = loc
            d["history"] = [
                {"old": h.old_status, "new": h.new_status, "note": h.note, "ts": h.ts}
                for h in repo.finding_history(fid)
            ]
            d["evidence"] = [
                {"kind": e.kind, "path": e.path, "description": e.description}
                for e in repo.list_evidence() if e.finding_id == fid
            ]
            return d
        finally:
            repo.close()

    @app.get("/api/project/{name}/graph")
    def api_graph(name: str):
        name = resolve(name)
        repo = _repo(name)
        try:
            hosts = repo.list_hosts()
            services = repo.list_services()
            findings = sorted(repo.list_findings(),
                              key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
            return {
                "hosts": [
                    {"id": h.id, "address": h.address,
                     "label": (h.hostname or h.address)} for h in hosts
                ],
                "services": [
                    {"id": s.id, "host_id": s.host_id,
                     "label": f"{s.port}/{s.protocol} {s.name or ''}".strip()}
                    for s in services
                ],
                "findings": [
                    {"id": f.id, "title": f.title, "severity": f.severity.value,
                     "status": f.status.value, "host_id": f.host_id,
                     "service_id": f.service_id} for f in findings
                ],
            }
        finally:
            repo.close()

    @app.post("/api/project/{name}/finding/{fid}/status")
    def api_set_status(name: str, fid: int, request: Request,
                       payload: dict = Body(...)):
        _guard_write(request)
        name = resolve(name)
        status = (payload or {}).get("status", "").strip()
        note = (payload or {}).get("note") or None
        if status not in _VALID_STATUS:
            raise HTTPException(422, f"Ungültiger Status. Erlaubt: {sorted(_VALID_STATUS)}")
        repo = _repo(name)
        try:
            ok = repo.set_finding_status(fid, status, note=note)
            if not ok:
                raise HTTPException(404, f"Finding {fid} nicht gefunden.")
            return {"ok": True, "id": fid, "status": status}
        finally:
            repo.close()

    @app.post("/api/project/{name}/notes")
    def api_add_note(name: str, request: Request, payload: dict = Body(...)):
        _guard_write(request)
        name = resolve(name)
        from ..models import Note
        title = (payload or {}).get("title", "").strip()
        body = (payload or {}).get("body", "").strip()
        category = (payload or {}).get("category") or None
        if not title:
            raise HTTPException(422, "Titel erforderlich.")
        repo = _repo(name)
        try:
            n = repo.add_note(Note(title=title, body=body, category=category))
            return {"ok": True, "id": n.id, "title": n.title}
        finally:
            repo.close()

    @app.get("/api/meta")
    def api_meta():
        from ..models import FindingStatus
        return {"statuses": [s.value for s in FindingStatus]}

    # ── Frontend (statisches SPA) ────────────────────────────────────────────
    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def serve(project: Optional[str] = None, host: str = "127.0.0.1", port: int = 8787):
    """Startet den uvicorn-Server (blockierend)."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise SystemExit(
            "uvicorn fehlt. Installiere die Web-Extras: pip install -e \".[web]\""
        ) from exc
    app = create_app(project, _bind_host=host, _bind_port=port)
    uvicorn.run(app, host=host, port=port, log_level="warning")
