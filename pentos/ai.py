"""
KI-Mentor für PentOS.

Lokale-zuerst-Anbindung an Ollama / LM Studio / OpenAI-kompatible Endpoints
mit Offline-Fallback. Die KI ist reiner Lern- und Analyseassistent:
sie erklärt, fasst zusammen und liefert Enumeration-Ideen. Sie führt NIEMALS
selbst Angriffe oder Befehle aus – dieses Tool ruft generell keine Exploits auf.

"""
from __future__ import annotations

import os
import re
from typing import Optional

import requests

from .models import Finding, Service

SYSTEM_PROMPT = (
    "Du bist ein lokaler Lern- und Analyseassistent für autorisiertes Penetration-Testing "
    "(CTF, TryHackMe, freigegebene Engagements). Antworte knapp und präzise auf Deutsch. "
    "Du erklärst Konzepte, Findings, Technologien und Methodik und schlägst Enumeration-Schritte vor. "
    "Du führst niemals selbst Aktionen aus und gehst von einem autorisierten Kontext aus."
)


def _strip_think(text: Optional[str]) -> Optional[str]:
    """Entfernt <think>...</think>-Reasoning-Blöcke (z.B. von deepseek-r1) aus der Antwort."""
    if not text:
        return text
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # offener <think> ohne Abschluss -> Rest verwerfen
    if "<think>" in cleaned.lower() and "</think>" not in cleaned.lower():
        cleaned = re.sub(r"<think>.*", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    # verwaiste Tags entfernen
    cleaned = re.sub(r"</?think>", "", cleaned, flags=re.IGNORECASE)
    return cleaned.strip()


class AIClient:
    def __init__(self, ai_config: dict, language: str = "de"):
        self.provider = (ai_config.get("provider") or "none").lower()
        self.base_url = (ai_config.get("base_url") or "").rstrip("/")
        self.model = ai_config.get("model") or ""
        self.embed_model = ai_config.get("embed_model") or "nomic-embed-text"
        self.api_key_env = ai_config.get("api_key_env") or "OPENAI_API_KEY"
        self.timeout = int(ai_config.get("timeout") or 60)
        self.language = (language or "de").lower()

    def available(self) -> bool:
        return self.provider in ("ollama", "lmstudio", "openai")

    def ping(self, timeout: Optional[int] = None) -> dict:
        """Prüft Erreichbarkeit des Backends und listet verfügbare Modelle."""
        info = {
            "provider": self.provider, "base_url": self.base_url,
            "model": self.model, "ok": False, "models": [], "error": None,
        }
        if self.provider == "none":
            info["error"] = "Provider ist 'none' (reiner Offline-Modus)."
            return info
        t = timeout or min(self.timeout, 8)
        try:
            if self.provider == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=t)
                r.raise_for_status()
                info["models"] = [m.get("name") for m in r.json().get("models", [])]
            else:  # lmstudio / openai
                headers = {}
                if self.provider == "openai":
                    key = os.environ.get(self.api_key_env)
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                r = requests.get(f"{self.base_url}/v1/models", headers=headers, timeout=t)
                r.raise_for_status()
                info["models"] = [m.get("id") for m in r.json().get("data", [])]
            info["ok"] = True
        except Exception as e:
            info["error"] = str(e)
        return info

    def _ask(self, user_prompt: str) -> Optional[str]:
        """Fragt das konfigurierte Backend. Gibt None bei Provider 'none' oder Fehler."""
        try:
            if self.provider == "ollama":
                resp = requests.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        "stream": False,
                    },
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return _strip_think(resp.json().get("message", {}).get("content"))

            if self.provider in ("lmstudio", "openai"):
                headers = {}
                if self.provider == "openai":
                    key = os.environ.get(self.api_key_env)
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                resp = requests.post(
                    f"{self.base_url}/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.3,
                    },
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return _strip_think(resp.json()["choices"][0]["message"]["content"])
        except Exception:
            return None
        return None

    # ── Embeddings (für RAG) ─────────────────────────────────────────────────
    def embed(self, text: str) -> Optional[list[float]]:
        """Erzeugt ein Embedding für RAG. None bei Fehler/Provider 'none'."""
        if self.provider == "none" or not text:
            return None
        try:
            if self.provider == "ollama":
                resp = requests.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.embed_model, "prompt": text},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                vec = resp.json().get("embedding")
                return vec if isinstance(vec, list) and vec else None
            # OpenAI-kompatibel (LM Studio / OpenAI)
            headers = {}
            if self.provider == "openai":
                key = os.environ.get(self.api_key_env)
                if key:
                    headers["Authorization"] = f"Bearer {key}"
            resp = requests.post(
                f"{self.base_url}/v1/embeddings",
                headers=headers,
                json={"model": self.embed_model, "input": text},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data") or []
            return data[0].get("embedding") if data else None
        except Exception:
            return None

    def answer_with_context(self, question: str, contexts: list[str]) -> Optional[str]:
        """Beantwortet eine Frage ausschließlich auf Basis des Projektkontexts (RAG)."""
        if self.provider == "none":
            return None
        if self.language == "en":
            system = (
                "You are a local assistant for an authorized penetration-testing project. "
                "Answer ONLY based on the provided project context. If the context does not "
                "contain the answer, say so explicitly – do NOT invent facts. Cite sources as "
                "[Type #id]. Be concise."
            )
            ctx_label, q_label = "Project context", "Question"
        else:
            system = (
                "Du bist ein lokaler Assistent für ein autorisiertes Pentest-Projekt. "
                "Beantworte die Frage AUSSCHLIESSLICH auf Basis des bereitgestellten "
                "Projektkontexts. Fehlt die Information im Kontext, sage das klar – erfinde "
                "NICHTS. Zitiere Quellen als [Typ #id]. Antworte knapp."
            )
            ctx_label, q_label = "Projektkontext", "Frage"
        ctx = "\n".join(f"- {c}" for c in contexts) if contexts else "(leer)"
        prompt = f"{ctx_label}:\n{ctx}\n\n{q_label}: {question}"
        return self._ask_system(system, prompt)

    def _ask_system(self, system: str, user_prompt: str) -> Optional[str]:
        """Wie _ask, aber mit explizitem System-Prompt (für RAG/Sprachsteuerung)."""
        try:
            if self.provider == "ollama":
                resp = requests.post(
                    f"{self.base_url}/api/chat",
                    json={"model": self.model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user_prompt}],
                          "stream": False},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return _strip_think(resp.json().get("message", {}).get("content"))
            if self.provider in ("lmstudio", "openai"):
                headers = {}
                if self.provider == "openai":
                    key = os.environ.get(self.api_key_env)
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                resp = requests.post(
                    f"{self.base_url}/v1/chat/completions",
                    headers=headers,
                    json={"model": self.model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user_prompt}],
                          "temperature": 0.2},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return _strip_think(resp.json()["choices"][0]["message"]["content"])
        except Exception:
            return None
        return None
        prompt = (
            f"Erkläre dieses Finding für einen lernenden Pentester:\n"
            f"Titel: {f.title}\nKategorie: {f.category.value}\nSeverity: {f.severity.value}\n"
            f"Beschreibung: {f.description or '-'}\n\n"
            f"Erkläre: Was ist das? Warum ein Risiko? Wie verifiziert man es manuell? "
            f"Wie behebt man es? Halte es kompakt."
        )
        answer = self._ask(prompt)
        return answer or _offline_finding(f)

    def enumeration_ideas(self, svc: Service) -> str:
        prompt = (
            f"Service: Port {svc.port}/{svc.protocol}, Name {svc.name or '-'}, "
            f"Produkt {svc.product or '-'}, Version {svc.version or '-'}.\n"
            f"Gib eine kompakte, priorisierte Enumeration-Checkliste für autorisiertes Testing."
        )
        answer = self._ask(prompt)
        return answer or _offline_enum(svc)

    # ── Advisor: aktive, konkrete Vorschläge (Human-in-the-Loop) ──────────────
    def _advisor_system(self, advisor: bool) -> str:
        """System-Prompt für den Berater-Modus. Die KI SCHLÄGT VOR, führt NIE aus."""
        base_de = (
            "Du bist ein erfahrener Pentest-Mentor für ein autorisiertes Projekt "
            "(CTF/Lab/freigegebene Tests). Du analysierst und EMPFIEHLST – du führst "
            "selbst NICHTS aus. Vorgeschlagene Befehle sind Vorschläge, die der Mensch "
            "prüft und selbst startet. Erfinde keine Fakten; wenn etwas unklar ist, sag es."
        )
        if advisor:
            return base_de + (
                " Sei konkret und taktisch: Nenne die nächsten 2–3 sinnvollsten Schritte, "
                "jeweils mit (a) kurzer Begründung und (b) einem konkreten Befehl als "
                "`pentos run …`- oder Shell-Vorschlag. Priorisiere nach Erfolgswahrscheinlichkeit."
            )
        return base_de + " Halte dich knapp und erklärend, ohne zu drängen."

    def next_steps(self, state_text: str, advisor: bool = True) -> Optional[str]:
        """Schlägt auf Basis des Projektstands die nächsten Schritte vor."""
        if self.provider == "none":
            return None
        prompt = (
            "Hier ist der aktuelle Stand eines Pentest-Projekts. Was sind die nächsten "
            "sinnvollen Schritte?\n\n" + state_text
        )
        return self._ask_system(self._advisor_system(advisor), prompt)

    def interpret_output(self, tool: str, output: str, advisor: bool = True) -> Optional[str]:
        """Deutet eine Tool-Ausgabe: was steht da, was ist auffällig, was als Nächstes."""
        if self.provider == "none":
            return None
        snippet = output[:6000]
        prompt = (
            f"Deute die folgende Ausgabe von '{tool}'. Erkläre kurz: Was zeigt sie? "
            f"Was ist sicherheitsrelevant/auffällig? Was sind die nächsten sinnvollen "
            f"Schritte (mit konkretem Befehl)?\n\n```\n{snippet}\n```"
        )
        return self._ask_system(self._advisor_system(advisor), prompt)


# ── Offline-Fallbacks (keine Backend-Verbindung) ──────────────────────────────
def _offline_finding(f: Finding) -> str:
    return (
        f"[Offline-Modus]\n"
        f"Finding: {f.title} ({f.severity.value}, {f.category.value})\n"
        f"{f.description or ''}\n\n"
        f"Vorgehen: 1) Befund manuell reproduzieren  2) Auswirkung/Scope bestimmen  "
        f"3) Beweis (Screenshot/Output) sichern  4) Gegenmassnahme dokumentieren.\n"
        f"(Tipp: lokales Modell via Ollama/LM Studio aktivieren für ausführliche Erklärungen.)"
    )


def _offline_enum(svc: Service) -> str:
    from .recommend import recommendations_for
    recs = recommendations_for(svc)
    bullets = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs))
    return (
        f"[Offline-Modus] Enumeration für {svc.port}/{svc.protocol} ({svc.name or 'unbekannt'}):\n"
        f"{bullets}\n"
        f"(Tipp: lokales Modell aktivieren für kontextbezogene Vorschläge.)"
    )
