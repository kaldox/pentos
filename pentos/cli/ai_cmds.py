"""
CLI-Befehle: KI-Mentor (Advisor-Modus, RAG "Frag dein Projekt", Analyse).

Ausgelagert aus cli/app.py -- reine Verschiebung, kein Verhalten geändert.
`serve`/`mcp` (ebenfalls "KI & Integration") hängen direkt am Haupt-`app`
und bleiben deshalb in app.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel

from .. import config
from ..ai import AIClient
from ..models import Note
from ..runners import base as runner_base, parsers as runner_parsers, registry as runner_registry
from ._shared import console, SYM_ARROW, _repo


# ── KI-Mentor ────────────────────────────────────────────────────────────────
ai_app = typer.Typer(help="KI-Mentor (lokal, nur Analyse)")


@ai_app.command("status")
def ai_status():
    """Prüft, ob das konfigurierte KI-Backend erreichbar ist (inkl. Modelle)."""
    info = AIClient(config.load_config()["ai"]).ping()
    aicfg = config.load_config()["ai"]
    ok = "[green]erreichbar[/green]" if info["ok"] else "[red]nicht erreichbar[/red]"
    from ..ai import LANGUAGES
    lang = aicfg.get("language", "de")
    lines = [
        f"Provider:  {info['provider']}",
        f"Base-URL:  {info['base_url'] or '-'}",
        f"Modell:    {info['model'] or '-'}",
        f"Status:    {ok}",
        f"Sprache:   {LANGUAGES.get(lang, lang)}"
        + ("" if aicfg.get("language_set") else " [dim](noch nicht bewusst gewählt)[/dim]"),
        f"Auto-Modell: {'an' if aicfg.get('auto_model') else 'aus'}"
        f"   Verbosity: {aicfg.get('verbosity', 'normal')}"
        f"   Temp: {aicfg.get('temperature', 0.3)}",
    ]
    if aicfg.get("persona"):
        lines.append(f"Persona:   {aicfg['persona']}")
    if aicfg.get("models"):
        pairs = ", ".join(f"{t}={m}" for t, m in aicfg["models"].items())
        lines.append(f"Pro-Task:  {pairs}")
    if info["ok"]:
        models = [m for m in info["models"] if m]
        lines.append(f"Modelle:   {', '.join(models) if models else '(keine gefunden)'}")
        if info["model"] and models and info["model"] not in models:
            lines.append(f"[yellow]Hinweis: '{info['model']}' nicht installiert — "
                         f"z.B. 'ollama pull {info['model']}'.[/yellow]")
    if info["error"]:
        lines.append(f"[red]Fehler: {info['error']}[/red]")
        if info["provider"] != "none":
            lines.append("[dim]Checkliste: Ollama mit OLLAMA_HOST=0.0.0.0 gestartet? "
                         "Port 11434 in der Firewall offen? IP/Route von der VM erreichbar "
                         "(curl http://<ip>:11434/api/tags)?[/dim]")
        else:
            lines.append("[dim]Backend aktivieren: pentos ai config --provider ollama "
                         "--base-url http://<ip>:11434 --model <modell>[/dim]")
    console.print(Panel("\n".join(lines), title="KI-Status"))


@ai_app.command("config")
def ai_config(provider: Optional[str] = typer.Option(None, "--provider",
                                                     help="ollama | lmstudio | openai | none"),
              base_url: Optional[str] = typer.Option(None, "--base-url",
                                                     help="z.B. http://192.168.1.20:11434"),
              model: Optional[str] = typer.Option(None, "--model", help="z.B. llama3.1"),
              embed_model: Optional[str] = typer.Option(None, "--embed-model",
                                                         help="Embedding-Modell für RAG, z.B. nomic-embed-text"),
              timeout: Optional[int] = typer.Option(None, "--timeout"),
              api_key_env: Optional[str] = typer.Option(None, "--api-key-env"),
              advisor: Optional[bool] = typer.Option(None, "--advisor/--no-advisor",
                                                     help="Aktive Vorschläge an/aus (Human-in-the-Loop)"),
              language: Optional[str] = typer.Option(None, "--language", "--lang",
                                                     help="Ausgabesprache: de,en,es,fr,zh,hi,ar,pt,ru,ja oder Freitext"),
              auto_model: Optional[bool] = typer.Option(None, "--auto-model/--no-auto-model",
                                                        help="Bestes installiertes Modell je Aufgabe wählen"),
              persona: Optional[str] = typer.Option(None, "--persona",
                                                    help="Zusatz-System-Prompt, z.B. 'knapper OSCP-Mentor'"),
              temperature: Optional[float] = typer.Option(None, "--temperature", help="0.0-1.0"),
              verbosity: Optional[str] = typer.Option(None, "--verbosity",
                                                      help="concise | normal | detailed"),
              keep_terms: Optional[bool] = typer.Option(None, "--keep-terms/--no-keep-terms",
                                                        help="Fachbegriffe/CVEs im Original lassen"),
              model_for: list[str] = typer.Option(None, "--model-for",
                                                  help="Pro-Task-Modell, z.B. analyze=deepseek-r1:14b (mehrfach)"),
              check: bool = typer.Option(True, "--check/--no-check",
                                         help="Nach dem Speichern Erreichbarkeit prüfen")):
    """Setzt die KI-Anbindung und das KI-Verhalten (schreibt in config.yaml)."""
    valid = {"ollama", "lmstudio", "openai", "none"}
    if provider and provider not in valid:
        console.print(f"[red]Unbekannter Provider '{provider}'.[/red] Erlaubt: {', '.join(sorted(valid))}")
        raise typer.Exit(1)
    if verbosity and verbosity not in {"concise", "normal", "detailed"}:
        console.print("[red]verbosity: concise | normal | detailed[/red]"); raise typer.Exit(1)
    cfg = config.load_config()
    ai = dict(cfg.get("ai", {}))
    if provider: ai["provider"] = provider
    if base_url: ai["base_url"] = base_url
    if model: ai["model"] = model
    if embed_model: ai["embed_model"] = embed_model
    if timeout: ai["timeout"] = timeout
    if api_key_env: ai["api_key_env"] = api_key_env
    if advisor is not None: ai["advisor"] = advisor
    if language:
        ai["language"] = language.lower(); ai["language_set"] = True
    if auto_model is not None: ai["auto_model"] = auto_model
    if persona is not None: ai["persona"] = persona
    if temperature is not None: ai["temperature"] = max(0.0, min(1.0, temperature))
    if verbosity: ai["verbosity"] = verbosity
    if keep_terms is not None: ai["keep_terms"] = keep_terms
    if model_for:
        models = dict(ai.get("models") or {})
        for pair in model_for:
            if "=" in pair:
                t, m = pair.split("=", 1)
                models[t.strip()] = m.strip()
        ai["models"] = models
    cfg["ai"] = ai
    path = config.save_config(cfg)
    console.print(f"[green]Config gespeichert:[/green] {path}")
    console.print(f"  provider={ai.get('provider')}  base_url={ai.get('base_url')}  "
                  f"model={ai.get('model')}  sprache={ai.get('language')}  "
                  f"auto-modell={ai.get('auto_model')}")
    if check and ai.get("provider") not in (None, "none"):
        ai_status()


@ai_app.command("explain-finding")
def ai_explain_finding(finding_id: int,
                       lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache"),
                       yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    repo.close()
    if not f:
        console.print("[red]Finding nicht gefunden.[/red]"); raise typer.Exit(1)
    _ensure_language()
    client = _ai_client(lang)
    if not _confirm_ai_send(client, f"Finding #{finding_id} ('{f.title}')", yes):
        console.print("Abgebrochen."); raise typer.Exit()
    console.print(Panel(client.explain_finding(f), title=f"KI-Mentor · Finding #{finding_id}"))


@ai_app.command("enum")
def ai_enum(service_id: int,
            lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache"),
            yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    repo, _ = _repo()
    svc = repo.get_service(service_id)
    repo.close()
    if not svc:
        console.print("[red]Service nicht gefunden.[/red]"); raise typer.Exit(1)
    _ensure_language()
    client = _ai_client(lang)
    if not _confirm_ai_send(client, f"Service {svc.port}/{svc.protocol}", yes):
        console.print("Abgebrochen."); raise typer.Exit()
    console.print(Panel(client.enumeration_ideas(svc),
                        title=f"KI-Mentor · Enumeration {svc.port}/{svc.protocol}"))


def _ai_client(lang: Optional[str] = None) -> AIClient:
    cfg = config.load_config()
    ai = dict(cfg["ai"])
    if lang:                       # Pro-Befehl-Override
        ai["language"] = lang.lower()
    return AIClient(ai, language=cfg.get("language", "de"))


def _ensure_language() -> None:
    """Fragt einmalig die Ausgabesprache ab, falls noch nie bewusst gewählt."""
    cfg = config.load_config()
    ai = cfg.get("ai", {})
    if ai.get("language_set") or ai.get("provider") in (None, "none"):
        return
    if not sys.stdin.isatty():     # nicht-interaktiv (Pipe/CI) -> nicht fragen
        return
    from ..ai import LANGUAGES
    console.print("[bold]In welcher Sprache soll die KI antworten?[/bold]")
    codes = list(LANGUAGES.keys())
    for i, code in enumerate(codes, 1):
        console.print(f"  {i}. {LANGUAGES[code]} [dim]({code})[/dim]")
    console.print(f"  {len(codes)+1}. Andere (Code eingeben)")
    choice = typer.prompt("Auswahl", default="1")
    code = ai.get("language", "de")
    if choice.isdigit() and 1 <= int(choice) <= len(codes):
        code = codes[int(choice) - 1]
    elif choice.isdigit() and int(choice) == len(codes) + 1:
        code = typer.prompt("Sprachcode/-name").strip().lower() or code
    elif choice.strip():
        code = choice.strip().lower()
    ai = dict(ai); ai["language"] = code; ai["language_set"] = True
    cfg["ai"] = ai; config.save_config(cfg)
    console.print(f"[green]Sprache gesetzt:[/green] {LANGUAGES.get(code, code)} "
                  f"[dim](änderbar mit pentos ai config --language ..)[/dim]\n")


def _stream_to_console(title: str):
    """Gibt einen on_token-Callback zurück, der live in ein Rich-Panel/Plain schreibt."""
    console.print(f"[dim]-- {title} --[/dim]")

    def on_token(t: str):
        console.print(t, end="", markup=False, highlight=False)
    return on_token


@ai_app.command("index")
def ai_index():
    """Baut den RAG-Index über die Projektdaten neu (Embeddings via KI-Backend)."""
    from .. import rag
    client = _ai_client()
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        raise typer.Exit(1)
    repo, name = _repo()
    console.print(f"[dim]Indexiere Projekt '{name}' mit Embedding-Modell "
                  f"'{client.embed_model}' …[/dim]")
    ok, fail = rag.index_project(repo, client.embed)
    repo.close()
    if ok == 0:
        console.print("[red]Keine Embeddings erzeugt.[/red] Backend erreichbar? "
                      f"Modell '{client.embed_model}' installiert? "
                      f"([cyan]ollama pull {client.embed_model}[/cyan])")
        raise typer.Exit(1)
    msg = f"[green]Index aufgebaut:[/green] {ok} Einträge"
    if fail:
        msg += f" ([yellow]{fail} übersprungen[/yellow])"
    console.print(msg)


@ai_app.command("ask")
def ai_ask(frage: str,
           k: int = typer.Option(5, "--k", help="Anzahl Kontext-Treffer"),
           lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
           stream: bool = typer.Option(False, "--stream", help="Antwort live streamen")):
    """Beantwortet eine Frage über die Projektdaten (RAG, mit Quellenangabe)."""
    from .. import rag
    _ensure_language()
    client = _ai_client(lang)
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        raise typer.Exit(1)
    repo, name = _repo()
    if repo.rag_count() == 0:
        repo.close()
        console.print("[yellow]Index ist leer.[/yellow] Erst aufbauen: [cyan]pentos ai index[/cyan]")
        raise typer.Exit(1)
    qvec = client.embed(frage)
    if not qvec:
        repo.close()
        console.print("[red]Frage konnte nicht eingebettet werden[/red] (Backend/Embedding-Modell?).")
        raise typer.Exit(1)
    hits = rag.search(repo, qvec, k=k)
    repo.close()
    contexts = [f"{h.label()}: {h.chunk}" for h in hits]
    if stream:
        answer = client.answer_with_context(frage, contexts, stream=True,
                                            on_token=_stream_to_console(f"Frag dein Projekt ({name})"))
        console.print()
    else:
        answer = client.answer_with_context(frage, contexts)
        if answer:
            console.print(Panel(answer, title=f"KI · Frag dein Projekt ({name})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar?).")
        raise typer.Exit(1)
    if hits:
        srcs = "  ".join(f"[dim]{h.label()} ({h.score:.2f})[/dim]" for h in hits)
        console.print(srcs)


def _confirm_ai_send(client: AIClient, what: str, yes: bool) -> bool:
    """Fragt vor dem Senden an die KI nach – warnt, wenn Daten den Rechner verlassen."""
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        return False
    if yes:
        return True
    if client.provider in ("ollama", "lmstudio"):
        # lokal -> Daten bleiben auf dem Rechner; leise Bestätigung
        return typer.confirm(f"{what} an lokales Modell ({client.provider}) senden?", default=True)
    # Cloud -> deutliche Warnung
    console.print(f"[yellow]Achtung:[/yellow] {what} wird an einen externen Anbieter "
                  f"([bold]{client.provider}[/bold]) gesendet – Daten verlassen deinen Rechner.")
    return typer.confirm("Wirklich senden?", default=False)


@ai_app.command("analyze")
def ai_analyze(
    file: Optional[Path] = typer.Argument(None, exists=True, readable=True,
                                          help="Datei mit Scan/Log/Output (oder --text)"),
    text: Optional[str] = typer.Option(None, "--text", help="Text direkt übergeben"),
    label: str = typer.Option("Output", "--as", help="Was ist das? z.B. nmap, ffuf, log"),
    save: bool = typer.Option(False, "--save", help="Ergebnis als Notiz im Projekt speichern"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden"),
    lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
    stream: bool = typer.Option(False, "--stream", help="Antwort live streamen"),
):
    """Füttert die KI mit einem Scan/Log/Output und bekommt eine Deutung + nächste Schritte.

    Beispiele:
      pentos ai analyze scan.txt --as nmap
      cat nikto.txt | pentos ai analyze --as nikto
      pentos ai analyze --text "$(ss -tlnp)" --as ports
    """
    # Eingabe sammeln: Datei, --text, oder stdin
    content = None
    if text is not None:
        content = text
    elif file is not None:
        content = file.read_text(encoding="utf-8", errors="ignore")
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    if not content or not content.strip():
        console.print("[red]Keine Eingabe.[/red] Datei, --text oder per Pipe (stdin) übergeben.")
        raise typer.Exit(1)

    _ensure_language()
    client = _ai_client(lang)
    cfg = config.load_config()
    if not _confirm_ai_send(client, f"'{label}'-Ausgabe ({len(content)} Zeichen)", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()

    advisor = bool(cfg["ai"].get("advisor", True))
    if stream:
        answer = client.interpret_output(label, content, advisor=advisor,
                                         stream=True, on_token=_stream_to_console(f"Analyse ({label})"))
        console.print()
    else:
        with console.status("[cyan]KI analysiert…[/cyan]"):
            answer = client.interpret_output(label, content, advisor=advisor)
        if answer:
            console.print(Panel(answer, title=f"KI · Analyse ({label})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)
    if save:
        repo, _ = _repo()
        repo.add_note(Note(title=f"KI-Analyse · {label}", body=answer, category="ai"))
        repo.close()
        console.print("[green]Als Notiz gespeichert.[/green]")


# pentos-run-Vorschläge aus der freien KI-Antwort herausfiltern (der Advisor-
# System-Prompt bittet gezielt um genau dieses Format). Nur Tool+Ziel, keine
# von der KI vorgeschlagenen Zusatz-Flags -- die werden bewusst ignoriert,
# damit nicht unbeaufsichtigt beliebige Optionen mitlaufen.
_AI_CMD_RE = re.compile(r"pentos run\s+([a-zA-Z0-9_.\-]+)\s+(\S+)")


def _extract_ai_commands(answer: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _AI_CMD_RE.finditer(answer or ""):
        tool, target = m.group(1), m.group(2).rstrip(".,;:`)")
        if runner_registry.get(tool) and (tool, target) not in out:
            out.append((tool, target))
    return out[:5]


def _run_tool_confirmed(repo, name: str, spec, target: str) -> bool:
    """Scope-Check + Ausführung + Ingest + Ergebnis-Panel für einen einzelnen,
    vom Menschen bereits bestätigten Lauf. Geteilte Logik für 'ai next --act'
    (die eigentliche Ausführung von 'pentos run' bleibt unverändert, deckt
    aber mehr Optionen ab als hier gebraucht werden)."""
    host = runner_base.host_of(target)
    if spec.network and repo.scope_defined() and not repo.in_scope(host):
        console.print(f"[red]'{host}' liegt nicht im definierten Scope.[/red] "
                      f"Erweitern mit: [cyan]pentos scope add {host}[/cyan]")
        return False
    scans_dir = config.project_path(name) / "scans"
    try:
        result = runner_base.run_tool(spec, target, scans_dir)
    except runner_base.RunnerError as e:
        console.print(f"[red]{e}[/red]")
        return False
    summary = runner_parsers.ingest(repo, spec, target, result, name)
    status = "[yellow]Timeout[/yellow]" if result.timed_out else f"rc={result.returncode}"
    console.print(Panel.fit(
        f"[bold]{spec.name}[/bold] {SYM_ARROW} {target}   ({status}, {result.duration_ms} ms)\n"
        f"Ausgabe: {result.output_path}\n"
        f"Neu: {summary['hosts']} Hosts · {summary['services']} Services · "
        f"{summary['tasks']} Tasks · {summary['findings']} Findings · "
        f"{summary['loot']} Loot · {summary['notes']} Notizen · {summary['evidence']} Evidence",
        title="Von der KI vorgeschlagen, von dir bestätigt"))
    return True


@ai_app.command("next")
def ai_next(yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden"),
            lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
            stream: bool = typer.Option(False, "--stream", help="Antwort live streamen"),
            act: bool = typer.Option(False, "--act",
                                     help="Aus der Antwort vorgeschlagene 'pentos run'-Befehle "
                                          "anbieten -- du wählst und bestätigst, bevor irgendetwas "
                                          "läuft. Ohne --act reine Textausgabe wie bisher.")):
    """Schlägt auf Basis des aktuellen Projektstands die nächsten sinnvollen Schritte vor."""
    repo, name = _repo()
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    notes = repo.list_notes()
    # kompakten Stand bauen
    lines = [f"Projekt: {name}", f"Hosts: {len(hosts)}, Services: {len(services)}, "
             f"Findings: {len(findings)}, Notizen: {len(notes)}", ""]
    for h in hosts:
        svcs = [s for s in services if s.host_id == h.id]
        lines.append(f"Host {h.address} ({h.hostname or '-'}, OS {h.os_guess or '?'}):")
        for s in svcs:
            lines.append(f"  - {s.port}/{s.protocol} {s.name or ''} {s.product or ''} {s.version or ''}".rstrip())
    if findings:
        lines.append("\nFindings:")
        for f in findings:
            lines.append(f"  - [{f.severity.value}] {f.title}")
    state = "\n".join(lines)
    repo.close()

    _ensure_language()
    client = _ai_client(lang)
    cfg = config.load_config()
    if not _confirm_ai_send(client, "den Projektstand", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()
    advisor = bool(cfg["ai"].get("advisor", True))
    if stream:
        answer = client.next_steps(state, advisor=advisor,
                                   stream=True, on_token=_stream_to_console(f"Nächste Schritte ({name})"))
        console.print()
    else:
        with console.status("[cyan]KI denkt über die nächsten Schritte nach…[/cyan]"):
            answer = client.next_steps(state, advisor=advisor)
        if answer:
            console.print(Panel(answer, title=f"KI · Nächste Schritte ({name})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)

    if not act:
        return

    candidates = _extract_ai_commands(answer)
    if not candidates:
        console.print("\n[dim]Keine ausführbare 'pentos run <tool> <ziel>'-Empfehlung im "
                      "Antworttext gefunden -- nichts zum Bestätigen.[/dim]")
        return
    console.print("\n[bold]Vorgeschlagene Befehle (nur Tool + Ziel, Zusatz-Optionen der KI "
                  "werden ignoriert):[/bold]")
    for i, (tool, target) in enumerate(candidates, 1):
        console.print(f"  {i}. pentos run {tool} {target}")
    choice = typer.prompt("Welchen ausführen? (Nummer, Enter = keinen)", default="", show_default=False)
    if not choice.strip():
        console.print("Nichts ausgeführt.")
        return
    try:
        idx = int(choice.strip()) - 1
        if idx < 0:
            raise ValueError
        tool, target = candidates[idx]
    except (ValueError, IndexError):
        console.print("[red]Ungültige Auswahl.[/red]")
        raise typer.Exit(1)
    spec = runner_registry.get(tool)
    if not typer.confirm(f"'pentos run {tool} {target}' jetzt wirklich ausführen?", default=False):
        console.print("Abgebrochen.")
        return
    repo2, name2 = _repo()
    _run_tool_confirmed(repo2, name2, spec, target)
    repo2.close()
