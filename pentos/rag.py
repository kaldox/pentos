"""
RAG „Frag dein Projekt" für PentOS.

Baut aus den Projektdaten (Findings, Notizen, Wissen, Loot, Hosts, Services) einen
Korpus, erzeugt lokale Embeddings (über den AIClient -> Ollama/LM Studio/OpenAI)
und legt sie als Vektor-Index in der per-Projekt-SQLite ab. Eine Frage wird
eingebettet, per Cosine-Ähnlichkeit gegen den Index gesucht und die besten Treffer
als Kontext an das Sprachmodell gegeben (mit Quellenangabe, ohne Halluzination).

Die Embedding-Funktion wird injiziert (typischerweise AIClient.embed), damit das
Modul unabhängig vom Backend testbar bleibt.

"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Callable, Optional

from .repository import Repository

EmbedFn = Callable[[str], Optional[list[float]]]


@dataclass
class Doc:
    doc_type: str
    doc_id: Optional[int]
    title: str
    text: str


@dataclass
class Hit:
    doc_type: str
    doc_id: Optional[int]
    title: str
    chunk: str
    score: float

    def label(self) -> str:
        return f"[{self.doc_type} #{self.doc_id}] {self.title}" if self.doc_id else f"[{self.doc_type}] {self.title}"


def build_corpus(repo: Repository) -> list[Doc]:
    """Stellt aus den Projektdaten durchsuchbare Dokumente zusammen."""
    docs: list[Doc] = []

    for f in repo.list_findings():
        text = (f"Finding: {f.title}. Severity {f.severity.value}, Kategorie {f.category.value}, "
                f"Status {f.status.value}. {f.description or ''}").strip()
        docs.append(Doc("finding", f.id, f.title, text))

    for n in repo.list_notes():
        docs.append(Doc("note", n.id, n.title, f"Notiz: {n.title}. {n.body or ''}".strip()))

    for k in repo.list_knowledge():
        docs.append(Doc("knowledge", k.id, k.title,
                         f"Wissen [{k.tag}]: {k.title}. {k.body or ''}".strip()))

    for l in repo.list_loot():
        docs.append(Doc("loot", l.id, l.label,
                         f"Loot ({l.type.value}): {l.label}. Quelle: {l.source or '-'}".strip()))

    hosts = {h.id: h for h in repo.list_hosts()}
    for h in hosts.values():
        docs.append(Doc("host", h.id, h.address,
                         f"Host {h.address} ({h.hostname or '-'}), OS {h.os_guess or '-'}".strip()))

    for s in repo.list_services():
        addr = hosts[s.host_id].address if s.host_id in hosts else "?"
        docs.append(Doc("service", s.id, f"{addr}:{s.port}",
                         f"Dienst {addr}:{s.port}/{s.protocol} {s.name or ''} "
                         f"{s.product or ''} {s.version or ''}".strip()))

    return [d for d in docs if d.text]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def index_project(repo: Repository, embed_fn: EmbedFn) -> tuple[int, int]:
    """Baut den Vektor-Index neu auf. Gibt (indexiert, fehlgeschlagen) zurück."""
    corpus = build_corpus(repo)
    repo.rag_clear()
    ok = fail = 0
    for d in corpus:
        vec = embed_fn(d.text)
        if not vec:
            fail += 1
            continue
        repo.rag_add(d.doc_type, d.doc_id, d.title, d.text, json.dumps(vec))
        ok += 1
    return ok, fail


def search(repo: Repository, query_vec: list[float], k: int = 5) -> list[Hit]:
    hits: list[Hit] = []
    for row in repo.rag_all():
        try:
            vec = json.loads(row["embedding"])
        except Exception:
            continue
        score = cosine(query_vec, vec)
        hits.append(Hit(row["doc_type"], row["doc_id"], row["title"] or "", row["chunk"], score))
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits[:k]
