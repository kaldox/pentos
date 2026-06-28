"""
Datenmodelle und Enums für PentOS.

Alle fachlichen Objekte (Host, Service, Finding, Task, ...) werden hier als
Pydantic-Modelle definiert. Die Persistenz übernimmt repository.py via SQLite;
diese Modelle dienen der Validierung, Serialisierung und der Logik.

"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> str:
    """ISO-Zeitstempel ohne Mikrosekunden – einheitlich für DB und Journal."""
    return datetime.now().replace(microsecond=0).isoformat(sep=" ")


# ──────────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────────
class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingStatus(str, Enum):
    UNVERIFIED = "Zu verifizieren"
    CONFIRMED = "Bestätigt"
    EXPLOITED = "Ausgenutzt"
    FALSE_POSITIVE = "False Positive"
    CLOSED = "Geschlossen"


class TaskStatus(str, Enum):
    OPEN = "Offen"
    IN_PROGRESS = "In Bearbeitung"
    DONE = "Erledigt"


class FindingCategory(str, Enum):
    MISCONFIG = "Misconfiguration"
    VULN = "Vulnerability"
    EXPOSURE = "Exposure"
    CREDENTIAL = "Credential"
    INFO_DISCLOSURE = "Information Disclosure"
    OTHER = "Other"


class LootType(str, Enum):
    CREDENTIAL = "Credential"
    HASH = "Hash"
    TOKEN = "Token"
    COOKIE = "Cookie"
    API_KEY = "API Key"
    SSH_KEY = "SSH Key"
    OTHER = "Other"


# Reihenfolge für Sortierung/Reporting (Critical zuerst)
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ──────────────────────────────────────────────────────────────────────────
# Fachliche Modelle
# ──────────────────────────────────────────────────────────────────────────
class Host(BaseModel):
    id: Optional[int] = None
    address: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    status: str = "up"
    notes: Optional[str] = None
    created_at: str = Field(default_factory=_now)


class Service(BaseModel):
    id: Optional[int] = None
    host_id: int
    port: int
    protocol: str = "tcp"
    name: Optional[str] = None          # z.B. http, smb, ldap
    product: Optional[str] = None       # z.B. Apache httpd
    version: Optional[str] = None
    extra: Optional[str] = None         # zusätzliche Infos / NSE-Output
    tunnel: Optional[str] = None        # z.B. ssl
    created_at: str = Field(default_factory=_now)


class Finding(BaseModel):
    id: Optional[int] = None
    title: str
    category: FindingCategory = FindingCategory.OTHER
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.UNVERIFIED
    description: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    host_id: Optional[int] = None
    service_id: Optional[int] = None
    auto: bool = False                  # automatisch erkannt?
    created_at: str = Field(default_factory=_now)


class Task(BaseModel):
    id: Optional[int] = None
    title: str
    status: TaskStatus = TaskStatus.OPEN
    source: Optional[str] = None        # woher stammt die Aufgabe (z.B. "smb auto")
    host_id: Optional[int] = None
    service_id: Optional[int] = None
    created_at: str = Field(default_factory=_now)
    dedup_scope: str = "service"        # "service" | "host" – nur für Auto-Dedup, nicht persistiert


class Note(BaseModel):
    id: Optional[int] = None
    title: str
    body: str = ""
    category: Optional[str] = None      # z.B. nmap, smb, web
    host_id: Optional[int] = None
    service_id: Optional[int] = None
    created_at: str = Field(default_factory=_now)


class JournalEntry(BaseModel):
    id: Optional[int] = None
    ts: str = Field(default_factory=_now)
    action: str
    detail: Optional[str] = None


class FindingStatusChange(BaseModel):
    """Ein Eintrag in der Status-Historie eines Findings (Retest-Tracking)."""
    id: Optional[int] = None
    finding_id: int
    old_status: Optional[str] = None     # None = Ersteintrag bei Erstellung
    new_status: str
    note: Optional[str] = None
    ts: str = Field(default_factory=_now)


class Loot(BaseModel):
    id: Optional[int] = None
    type: LootType = LootType.OTHER
    label: str
    value: Optional[str] = None
    host_id: Optional[int] = None
    source: Optional[str] = None
    created_at: str = Field(default_factory=_now)


class Evidence(BaseModel):
    id: Optional[int] = None
    kind: str = "file"                  # file, screenshot, output, config, html
    path: str
    description: Optional[str] = None
    finding_id: Optional[int] = None
    host_id: Optional[int] = None
    created_at: str = Field(default_factory=_now)


class KnowledgeEntry(BaseModel):
    id: Optional[int] = None
    tag: str                            # z.B. Jenkins, SMB, Linux-PrivEsc
    title: str
    body: str = ""
    created_at: str = Field(default_factory=_now)


class FindingTemplate(BaseModel):
    """Wiederverwendbare, geprüfte Finding-Vorlage (pro Projekt-DB).

    Eine Vorlage wird per `template apply` zu einem konkreten Finding im Projekt
    instanziiert. `key` ist ein eindeutiger Slug (für idempotentes Seeding).
    """
    id: Optional[int] = None
    key: str                            # eindeutiger Slug, z.B. "null-session"
    title: str
    category: FindingCategory = FindingCategory.OTHER
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: Optional[str] = None    # freie Liste/URLs, durch Zeilenumbruch getrennt
    builtin: bool = False               # aus der Wissensbasis vorbefüllt?
    created_at: str = Field(default_factory=_now)


class ScopeEntry(BaseModel):
    id: Optional[int] = None
    value: str                          # Host/Domain oder CIDR
    kind: str = "host"                  # host | cidr
    created_at: str = Field(default_factory=_now)


class RunRecord(BaseModel):
    id: Optional[int] = None
    tool: str
    target: Optional[str] = None
    command: Optional[str] = None
    returncode: Optional[int] = None
    output_path: Optional[str] = None
    duration_ms: Optional[int] = None
    started_at: str = Field(default_factory=_now)
