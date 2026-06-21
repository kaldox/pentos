"""
Runner-Kern für PentOS.

Führt externe Tools kontrolliert aus (kein Shell, festes argv, Timeout) und
legt die Rohausgabe im scans/-Verzeichnis des Projekts ab. Opt-in: ein Tool
läuft nur, wenn es explizit gestartet wird.

"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel


class ToolSpec(BaseModel):
    name: str
    binary: str
    category: str                       # recon | web | smb | dns | snmp | vuln | bruteforce | exploit | cracking
    argv: list[str]                     # Tokens mit {target} {outfile} {wordlist}
    produces_outfile: bool = False
    outfile_ext: str = "txt"
    timeout: int = 300
    description: str = ""
    needs_wordlist: bool = False
    default_wordlist: Optional[str] = None
    parser: Optional[str] = None        # Schlüssel für parsers.ingest
    network: bool = True                # False = offline (kein Scope-Check, z.B. Cracking)
    profiles: Optional[dict[str, list[str]]] = None   # benannte argv-Varianten (z.B. nmap)


@dataclass
class RunResult:
    command: list[str]
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    output_path: Optional[str] = None
    started_at: str = ""
    timed_out: bool = False
    dry: bool = False


class RunnerError(Exception):
    pass


def _safe(name: str) -> str:
    keep = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c if c in keep else "_" for c in name) or "ziel"


def host_of(target: str) -> str:
    """Extrahiert den Host-Teil aus URL / host:port / host."""
    if "://" in target:
        h = urlparse(target).hostname
        return h or target
    if target.count(":") == 1 and not target.startswith("["):
        return target.split(":")[0]
    return target


def build_argv(template: list[str], spec: ToolSpec, target: str, outfile: Optional[Path],
               wordlist: Optional[str], extra_args: Optional[list[str]]) -> list[str]:
    wl = wordlist or spec.default_wordlist or ""
    argv: list[str] = []
    for tok in template:
        tok = tok.replace("{target}", target)
        if "{outfile}" in tok:
            tok = tok.replace("{outfile}", str(outfile) if outfile else "")
        if "{wordlist}" in tok:
            tok = tok.replace("{wordlist}", wl)
        argv.append(tok)
    if extra_args:
        argv.extend(extra_args)
    return argv


def run_tool(spec: ToolSpec, target: str, scans_dir: Path,
             extra_args: Optional[list[str]] = None,
             wordlist: Optional[str] = None,
             timeout: Optional[int] = None,
             dry_run: bool = False,
             profile: Optional[str] = None,
             shell: bool = False,
             raw_args: Optional[str] = None) -> RunResult:
    scans_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    outfile = None
    if spec.produces_outfile and not shell:
        outfile = scans_dir / f"{spec.name}_{_safe(host_of(target))}_{ts}.{spec.outfile_ext}"

    # Template wählen: Profil > Default-argv
    template = spec.argv
    if profile:
        if not spec.profiles or profile not in spec.profiles:
            avail = ", ".join(spec.profiles) if spec.profiles else "keine"
            raise RunnerError(f"Profil '{profile}' für {spec.name} unbekannt. Verfügbar: {avail}")
        template = spec.profiles[profile]

    # Kommando bauen.
    #   Standard: festes argv, KEINE Shell -> keine Shell-Metazeichen-Interpretation.
    #   --shell:  bewusster Shell-Modus für interaktive Tools (z.B. smbclient -c '...').
    #             argv-Template wird ignoriert; der Nutzer steuert die Argumente selbst.
    #             ACHTUNG: Shell-Injection möglich – nur mit vertrauenswürdiger Eingabe.
    cmd_str = ""
    if shell:
        wl = wordlist or spec.default_wordlist or ""
        raw = (raw_args or "").replace("{target}", target).replace("{wordlist}", wl)
        cmd_str = f"{spec.binary} {raw}".strip()
        command_repr = [cmd_str]
    else:
        argv = build_argv(template, spec, target, outfile, wordlist, extra_args)
        command_repr = argv

    started = datetime.now().replace(microsecond=0).isoformat(sep=" ")

    if dry_run:
        return RunResult(command=command_repr, started_at=started,
                         output_path=str(outfile) if outfile else None, dry=True)

    if shutil.which(spec.binary) is None:
        raise RunnerError(f"Binary '{spec.binary}' nicht gefunden (in PATH). "
                          f"Installieren oder anderes Tool wählen.")

    eff_timeout = timeout or spec.timeout
    t0 = datetime.now()
    timed_out = False
    try:
        if shell:
            proc = subprocess.run(cmd_str, shell=True, capture_output=True, text=True,
                                  timeout=eff_timeout, check=False)
        else:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=eff_timeout, check=False)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc = None
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")) + \
              f"\n[Timeout nach {eff_timeout}s abgebrochen]"
    duration_ms = int((datetime.now() - t0).total_seconds() * 1000)

    # Ausgabe sichern: bei produces_outfile (Nicht-Shell) schreibt das Tool selbst;
    # im Shell-Modus oder ohne Ausgabedatei wird stdout in eine Capture-Datei gelegt.
    out_path = outfile
    if shell or not spec.produces_outfile:
        out_path = scans_dir / f"{spec.name}_{_safe(host_of(target))}_{ts}.txt"
        out_path.write_text(out + ("\n[stderr]\n" + err if err else ""), encoding="utf-8")

    return RunResult(command=command_repr, returncode=rc, stdout=out, stderr=err,
                     duration_ms=duration_ms, output_path=str(out_path) if out_path else None,
                     started_at=started, timed_out=timed_out)
