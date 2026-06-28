"""
KI-Mentor für PentOS.

Lokale-zuerst-Anbindung an Ollama / LM Studio / OpenAI-kompatible Endpoints
mit Offline-Fallback. Die KI ist reiner Lern- und Analyseassistent:
sie erklärt, fasst zusammen und liefert Enumeration-Ideen. Sie führt NIEMALS
selbst Angriffe oder Befehle aus – dieses Tool ruft generell keine Exploits auf.

"""
from __future__ import annotations

import json as _json
import os
import re
from typing import Optional

import requests

from .models import Finding, Service


class _ThinkStream:
    """Filtert <think>...</think>-Blöcke aus einem Token-Strom (für Streaming).

    Hält einen kleinen Puffer, damit über Chunk-Grenzen verteilte Tags erkannt
    werden, und gibt nur sichtbaren Text ausserhalb der Reasoning-Blöcke zurück.
    """
    def __init__(self):
        self.buf = ""
        self.in_think = False

    def feed(self, delta: str) -> str:
        self.buf += delta
        out = []
        while self.buf:
            if not self.in_think:
                i = self.buf.lower().find("<think>")
                if i == -1:
                    # evtl. unvollständiges Tag am Ende zurückhalten
                    keep = _tag_tail(self.buf, "<think>")
                    out.append(self.buf[:len(self.buf) - keep])
                    self.buf = self.buf[len(self.buf) - keep:]
                    break
                out.append(self.buf[:i])
                self.buf = self.buf[i + 7:]
                self.in_think = True
            else:
                j = self.buf.lower().find("</think>")
                if j == -1:
                    keep = _tag_tail(self.buf, "</think>")
                    self.buf = self.buf[len(self.buf) - keep:] if keep else ""
                    break
                self.buf = self.buf[j + 8:]
                self.in_think = False
        return "".join(out)


def _tag_tail(s: str, tag: str) -> int:
    """Länge eines möglichen unvollständigen Tag-Anfangs am String-Ende."""
    for n in range(len(tag) - 1, 0, -1):
        if s.lower().endswith(tag[:n]):
            return n
    return 0

SYSTEM_PROMPT = (
    "Du bist ein lokaler Lern- und Analyseassistent für autorisiertes Penetration-Testing "
    "(CTF, TryHackMe, freigegebene Engagements). Antworte knapp und präzise auf Deutsch. "
    "Du erklärst Konzepte, Findings, Technologien und Methodik und schlägst Enumeration-Schritte vor. "
    "Du führst niemals selbst Aktionen aus und gehst von einem autorisierten Kontext aus."
)

# Anzeigename je Sprachcode (Top-Sprachen + Freitext möglich).
LANGUAGES = {
    "de": "Deutsch", "en": "English", "es": "Español", "fr": "Français",
    "zh": "中文 (Chinese)", "hi": "हिन्दी (Hindi)", "ar": "العربية (Arabic)",
    "pt": "Português", "ru": "Русский (Russian)", "ja": "日本語 (Japanese)",
}

# Modell-Präferenz je Aufgabe (erstes installiertes wird gewählt, Prefix-Match).
TASK_PREFS = {
    "analyze": ["deepseek-r1:14b", "deepseek-r1", "qwen3:8b", "qwen3", "llama3.1", "gemma3:12b"],
    "next":    ["deepseek-r1:14b", "deepseek-r1", "qwen3:8b", "qwen3", "llama3.1", "gemma3:12b"],
    "explain": ["gemma3:12b", "gemma3", "llama3.1", "qwen3:8b", "deepseek-r1:8b"],
    "enum":    ["llama3.1", "qwen3:8b", "gemma3:12b", "deepseek-r1:8b"],
    "ask":     ["llama3.1:8b", "llama3.1", "qwen3:8b", "gemma3:12b"],
    "vision":  ["qwen3-vl", "llava", "bakllava", "minicpm-v", "llama3.2-vision"],
}


def _match_installed(pref: str, installed: list[str]) -> Optional[str]:
    """Findet ein installiertes Modell zu einem Präferenz-Eintrag (exakt oder Prefix)."""
    for m in installed:
        if m == pref:
            return m
    for m in installed:
        if m.startswith(pref):
            return m
    return None


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
        # Ausgabesprache: ai.language hat Vorrang vor dem übergebenen Default.
        self.language = (ai_config.get("language") or language or "de").lower()
        self.keep_terms = bool(ai_config.get("keep_terms", True))
        self.auto_model = bool(ai_config.get("auto_model", False))
        self.models = ai_config.get("models") or {}
        self.vision_model = ai_config.get("vision_model") or ""
        self.persona = (ai_config.get("persona") or "").strip()
        self.temperature = float(ai_config.get("temperature", 0.3))
        self.verbosity = (ai_config.get("verbosity") or "normal").lower()
        self._installed_cache: Optional[list[str]] = None

    # ── Modellwahl ───────────────────────────────────────────────────────────
    def _installed(self) -> list[str]:
        if self._installed_cache is None:
            self._installed_cache = self.ping().get("models") or []
        return self._installed_cache

    def candidates(self, task: Optional[str]) -> list[str]:
        """Geordnete Liste von Modell-Kandidaten für eine Aufgabe (für Fallback)."""
        out: list[str] = []
        explicit = self.models.get(task) if task else None
        if explicit:
            out.append(explicit)
        if task == "vision" and self.vision_model:
            out.append(self.vision_model)
        if self.auto_model and task in TASK_PREFS:
            installed = self._installed()
            for pref in TASK_PREFS[task]:
                m = _match_installed(pref, installed)
                if m and m not in out:
                    out.append(m)
        if self.model and self.model not in out:
            out.append(self.model)
        return out or ([self.model] if self.model else [])

    def select_model(self, task: Optional[str] = None) -> str:
        c = self.candidates(task)
        return c[0] if c else self.model

    # ── System-Prompt zusammensetzen (Sprache, Persona, Verbosity) ───────────
    def _lang_clause(self) -> str:
        name = LANGUAGES.get(self.language, self.language)
        clause = f" Antworte ausschliesslich auf {name}."
        if self.keep_terms:
            clause += (" Fachbegriffe, CVE-IDs, Tool- und Befehlsnamen sowie Code "
                       "bleiben im Original (nicht uebersetzen).")
        return clause

    def _verbosity_clause(self) -> str:
        if self.verbosity == "concise":
            return " Fasse dich sehr kurz, nur die Kernpunkte."
        if self.verbosity == "detailed":
            return " Antworte ausfuehrlich mit Begruendungen und Beispielen."
        return ""

    def _system(self, base: str) -> str:
        parts = [base]
        if self.persona:
            parts.append(self.persona)
        parts.append(self._lang_clause().strip())
        v = self._verbosity_clause().strip()
        if v:
            parts.append(v)
        return " ".join(p for p in parts if p)

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

    def _chat(self, system_base: str, user_prompt: str, *, task: Optional[str] = None,
              images: Optional[list[str]] = None, stream: bool = False,
              on_token=None) -> Optional[str]:
        """Zentraler Chat-Pfad: Modellwahl + Fallback-Kette, Sprache/Persona/Temperatur,
        optionales Streaming und Vision (images = Liste base64). Gibt None bei Fehler."""
        if self.provider == "none":
            return None
        system = self._system(system_base)
        last_err = None
        for model in self.candidates(task):
            try:
                if self.provider == "ollama":
                    return self._chat_ollama(model, system, user_prompt, images, stream, on_token)
                if self.provider in ("lmstudio", "openai"):
                    return self._chat_openai(model, system, user_prompt, images)
            except Exception as e:        # nächstes Modell aus der Kette versuchen
                last_err = e
                continue
        return None

    def _chat_ollama(self, model, system, user, images, stream, on_token):
        msg = {"role": "user", "content": user}
        if images:
            msg["images"] = images
        body = {"model": model,
                "messages": [{"role": "system", "content": system}, msg],
                "stream": bool(stream),
                "options": {"temperature": self.temperature}}
        if not stream:
            r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            return _strip_think(r.json().get("message", {}).get("content"))
        # Streaming: Zeilen-JSON, Reasoning live ausblenden
        flt = _ThinkStream()
        full = []
        with requests.post(f"{self.base_url}/api/chat", json=body,
                           timeout=self.timeout, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    chunk = _json.loads(line)
                except Exception:
                    continue
                delta = chunk.get("message", {}).get("content", "")
                if delta:
                    full.append(delta)
                    vis = flt.feed(delta)
                    if vis and on_token:
                        on_token(vis)
        return _strip_think("".join(full))

    def _chat_openai(self, model, system, user, images):
        headers = {}
        if self.provider == "openai":
            key = os.environ.get(self.api_key_env)
            if key:
                headers["Authorization"] = f"Bearer {key}"
        content = user
        if images:   # OpenAI-Vision-Format
            content = [{"type": "text", "text": user}] + [
                {"type": "image_url",
                 "image_url": {"url": f"data:image/png;base64,{b}"}} for b in images]
        r = requests.post(
            f"{self.base_url}/v1/chat/completions", headers=headers,
            json={"model": model,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": content}],
                  "temperature": self.temperature},
            timeout=self.timeout)
        r.raise_for_status()
        return _strip_think(r.json()["choices"][0]["message"]["content"])

    def _ask(self, user_prompt: str, task: Optional[str] = None) -> Optional[str]:
        """Standard-Frage mit Basis-System-Prompt (Kompatibilität)."""
        return self._chat(SYSTEM_PROMPT, user_prompt, task=task)

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

    def answer_with_context(self, question: str, contexts: list[str],
                            stream: bool = False, on_token=None) -> Optional[str]:
        """Beantwortet eine Frage ausschließlich auf Basis des Projektkontexts (RAG)."""
        if self.provider == "none":
            return None
        system = (
            "Du bist ein lokaler Assistent für ein autorisiertes Pentest-Projekt. "
            "Beantworte die Frage AUSSCHLIESSLICH auf Basis des bereitgestellten "
            "Projektkontexts. Fehlt die Information im Kontext, sage das klar - erfinde "
            "NICHTS. Zitiere Quellen als [Typ #id]."
        )
        ctx = "\n".join(f"- {c}" for c in contexts) if contexts else "(leer)"
        prompt = f"Projektkontext:\n{ctx}\n\nFrage: {question}"
        return self._chat(system, prompt, task="ask", stream=stream, on_token=on_token)

    def _ask_system(self, system: str, user_prompt: str,
                    task: Optional[str] = None) -> Optional[str]:
        """Frage mit explizitem Basis-System-Prompt (Sprache/Persona kommen oben drauf)."""
        return self._chat(system, user_prompt, task=task)

    def analyze_image(self, image_b64: str, question: Optional[str] = None) -> Optional[str]:
        """Wertet ein Bild (Screenshot, Dashboard, Diagramm) mit einem Vision-Modell aus."""
        if self.provider == "none":
            return None
        q = question or ("Beschreibe, was auf diesem Screenshot aus einem autorisierten "
                         "Pentest-Kontext zu sehen ist, und nenne sicherheitsrelevante "
                         "Auffälligkeiten und sinnvolle nächste Schritte.")
        system = (
            "Du bist ein Analyseassistent für autorisiertes Penetration-Testing. Du "
            "betrachtest Screenshots/Bilder, beschreibst Relevantes und schlägst Schritte "
            "vor. Du führst nichts aus."
        )
        return self._chat(system, q, task="vision", images=[image_b64])

    def explain_finding(self, f: Finding) -> str:
        prompt = (
            f"Erkläre dieses Finding für einen lernenden Pentester:\n"
            f"Titel: {f.title}\nKategorie: {f.category.value}\nSeverity: {f.severity.value}\n"
            f"Beschreibung: {f.description or '-'}\n\n"
            f"Erkläre: Was ist das? Warum ein Risiko? Wie verifiziert man es manuell? "
            f"Wie behebt man es? Halte es kompakt."
        )
        answer = self._ask(prompt, task="explain")
        return answer or _offline_finding(f)

    def enumeration_ideas(self, svc: Service) -> str:
        prompt = (
            f"Service: Port {svc.port}/{svc.protocol}, Name {svc.name or '-'}, "
            f"Produkt {svc.product or '-'}, Version {svc.version or '-'}.\n"
            f"Gib eine kompakte, priorisierte Enumeration-Checkliste für autorisiertes Testing."
        )
        answer = self._ask(prompt, task="enum")
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

    def next_steps(self, state_text: str, advisor: bool = True,
                   stream: bool = False, on_token=None) -> Optional[str]:
        """Schlägt auf Basis des Projektstands die nächsten Schritte vor."""
        if self.provider == "none":
            return None
        prompt = (
            "Hier ist der aktuelle Stand eines Pentest-Projekts. Was sind die nächsten "
            "sinnvollen Schritte?\n\n" + state_text
        )
        return self._chat(self._advisor_system(advisor), prompt, task="next",
                          stream=stream, on_token=on_token)

    def interpret_output(self, tool: str, output: str, advisor: bool = True,
                         stream: bool = False, on_token=None) -> Optional[str]:
        """Deutet eine Tool-Ausgabe: was steht da, was ist auffällig, was als Nächstes."""
        if self.provider == "none":
            return None
        snippet = output[:6000]
        prompt = (
            f"Deute die folgende Ausgabe von '{tool}'. Erkläre kurz: Was zeigt sie? "
            f"Was ist sicherheitsrelevant/auffällig? Was sind die nächsten sinnvollen "
            f"Schritte (mit konkretem Befehl)?\n\n```\n{snippet}\n```"
        )
        return self._chat(self._advisor_system(advisor), prompt, task="analyze",
                          stream=stream, on_token=on_token)


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
