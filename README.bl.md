# PentOS

[🇩🇪 Deutsch](README.md) · [🇬🇧 English](README.en.md) · **🐻 Baseldütsch**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.22.0%2Brunner-informational)

> ⚠️ **Experimentell:** Die Versjoon isch uf Baseldütsch gschriibe – churzwiilig gmeint, nid zwingend perfekt. Wär e Fähler findet, derf ne gärn flicke.

**E Pentest-Werchstatt, kei Scanner-Sammlig**

PentOS isch **kei Huffe Scanner**, sondern e ganzi Pentest-*Werchstatt*: Findings,
Aagriffspfäd, Notize, Bewiis, Wüsse und Dokumentation stöhn im Zentrum. Lokal-first,
kei Cloud-Zwang, dütschi Uusgaab. D KI isch nume zum Lärne und Analysiere doo –
**si macht sälber nie en Aagriff oder e Befähl**.

> Für autorisierts Teste: CTF, TryHackMe und Engagements wo unterschriibe sin.

---

## Was PentOS cha

| Funktion | Status |
|---|---|
| Pentest-Werchstatt (ganzi Ornerstruktur pro Projäkt) | ✅ |
| Automatischi Notize (z.B. `notes/nmap.md` bim Importiere) | ✅ |
| Pentest-Journal (jedi Aktion mit Ziitstämpel) | ✅ |
| Uufgabe-Sischtem (auto pro Dienscht, Offe/Am Schaffe/Fertig) | ✅ |
| Gschiidi nächschti Schritt (Vorschläg, **kei Uusfüehrig**) | ✅ |
| Gfüehrti Recon-/Enum-Chetti (`sweep`, rägelbasiert, Nochfrog pro Schritt) | ✅ |
| Opt-in Runner-Layer (23 Tools, kei Shell-Eval, Scope-Guard, Timeout) | ✅ |
| Methodik-/Playbook-Bibliothek (Web/AD/Linux-/Windows-PrivEsc) | ✅ |
| Automatischi Findings (rägelbasiert) + strukturierti Parser (enum4linux-ng, nuclei) | ✅ |
| Aagriffspfad-Graph (Mermaid + Graphviz-DOT) | ✅ |
| Obsidian-Integration (Vault mit `[[Wikilinks]]`) | ✅ |
| Loot-Verwaltig (Credentials/Hashes/Tokens/…) | ✅ |
| Bewiis-Verwaltig (Date/Screenshots/Outputs zuen eme Finding) | ✅ |
| **Bewiis/Screenshots im Report iibettet** (HTML inline, PDF, Markdown) | ✅ |
| Finding-Template-Bibliothek (wiederverwändbar, CVSS, vorbefüllt + erwiterbar) | ✅ |
| CTF/THM-Wüssensdatebank (taggti Iiträg) | ✅ |
| „Frog dis Projäkt" (RAG über eigeni Projäktdate, lokali Embeddings) | ✅ |
| KI-Mentor + **Advisor-Modus** (Scan/Log analysiere, nächschti Schritt; frogt vor em Sände; Offline-Fallback) | ✅ |
| Reporting: Markdown, **gebrandets HTML & PDF**, didaktische Lärn-Report | ✅ |
| **Web-Dashboard interaktiv** (Lagebild + Finding-Status ändere, Notize aalege im Browser) | ✅ |
| **MCP-Server** (Werchstatt uus Claude Code/Cursor abfroge, nume läsend) | ✅ |
| Import: nmap-XML **+ Scanner-Import (Nessus/OpenVAS/Burp)** | ✅ |

**Roadmap (offe):**
- KI-Lärnkarte & Notize-Zämmefassige (nume uus eigene Date, ohni Halluzination)
- Remediation-/Status-Gschicht für Findings (Retest-Tracking)
- Aagriffspfad-Graph visuell im Dashboard
- Bessers Screenshot-Handling (z.B. diräkt uufnäh und annotiere)

D ganzi Roadmap, mit Begründige und bewusste Nöd-Ziil, stoht in [`ROADMAP.md`](ROADMAP.md).

---

## Installiere

```bash
cd pentos
pip install -r requirements.txt
# optional als Befähl 'pentos' installiere:
pip install -e .
```

Ohni Installation lauft alles über `python -m pentos ...`.

Bim erschte Start wird `~/.config/pentos/config.yaml` automatisch aagleit
(lueg `config.example.yaml`). Eigene Pfad mit `export PENTOS_CONFIG=/pfad/config.yaml`.

---

## Schnällstart

```bash
# 1) Projäkt aalege (wird automatisch aktiv)
pentos project new THM_Alfred

# 2) Scan importiere  (nmap -sC -sV -oX scan.xml <ziil>)
pentos scan import-nmap scan.xml          # oder import-scanner für Nessus/OpenVAS/Burp
#   -> Hosts + Dienscht + Auto-Uufgabe + Auto-Findings + Auto-Notiz

# 3) Überblick & nächschti Schritt
pentos dashboard                          # kompakti Projäkt-Übersicht
pentos recommend 4                        # Vorschläg für e Dienscht (kei Uusfüehrig)

# 4) Schaffe dokumentiere
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./shot.png --kind screenshot --finding 4   # chunnt in Report

# 5) Report mache
pentos report --html                      # gebrandets HTML (au --pdf, --explain)
```

Das isch dr Chärn-Ablauf. Alli Befähl noch Bereich gruppiert in dr
**[Befähls-Referänz (COMMANDS.md)](COMMANDS.md)**, oder live mit `pentos --help`
und `pentos <gruppe> --help` (z.B. `pentos finding --help`).

---

## Runner-Layer (opt-in)

PentOS cha Tools au **sälber laufe loo** – aber nume wenn du si extra startsch
(`pentos run <tool> <ziil>`). Dr rohi Output landet in `scans/`, wird gläse und
automatisch in Findings/Tasks/Evidence/Notize gschoba und im Journal protokolliert.
E paar Tools wärte d Uusgaab grad uus: `nmap` macht di ganzi Host/Dienscht/Finding-
Pipeline, `nuclei` git Findings, `hydra`/`nxc` schriibe gfundeni Logins as Loot.

> **Shell-Modus (`--shell`)**: Standardmässig laufe Tools ohni Shell (fescht `argv`,
> kei Metazeiche-Eval, Injection-Schutz). Mängi Tools bruuche aber e richtigi Shell;
> `--shell` macht das bewusst aa. **Nume mit vertrouewürdige Iigaab bruuche.**

**Gfüehrti Chetti (`sweep`)** nimmt e Ziil, startet d Basis-Recon und schlat denn pro
Dienscht di nächschte Tools vor. Rägelbasiert, **kei autonome Agent**: sicheri Tools
chönne automatisch laufe (mit Nochfrog pro Schritt), Brute-Force/Exploits wärde **nie**
automatisch gmacht, nume vorgschlage.

**Playbooks** sin abhakbari Checkliste (Web, AD, Linux-/Windows-PrivEsc); dr Fortschritt
wird pro Projäkt gspeicheret. **„Frog dis Projäkt" (RAG)** beantwortet Froge über dini
eigene Date, nume uus em Projäkt-Kontext, ohni Halluzination.

**Scope-Guard:** Für echti Engagements legsch erlaubti Ziil fescht, damit nüt ussert em
Uuftrag lauft; ohni Scope lauft dr Runner uneigschränkt (CTF-Modus). Uusgfüehrt wird
immer ohni Shell und mit Timeout pro Tool. PentOS macht nüt vo sälber.

Di konkrete Befähl (Tools, `sweep`, Playbooks, RAG, Scope) stöhn in dr
**[Befähls-Referänz (COMMANDS.md)](COMMANDS.md)**.

---

## Sicherheit / Scope

PentOS orchestriert und dokumentiert – es macht **kei** Scans oder Exploits sälber.
Vorschläg sin Vorschläg, d KI analysiert nume. Bruuch nume in autorisierte Umgäbige
(eigeni Labor, CTF/THM, freigäbeni Tescht).

---

## Tescht

```bash
pip install pytest
pytest -q
```

---

## ⚠️ Haftigsuusschluss / Authorized Use Only

PentOS isch nume für **autorisierti** Sicherheitstescht doo: eigeni Labor,
CTF-Plattforme wie TryHackMe/Hack The Box, und Engagements mit **schriftlicher
Erlaubnis** vom Ziilinhaber. Bruuch gäge Sischtem ohni Erlaubnis isch in de meischte
Rächtsornige strofbar.

D Autore übernähmme **kei Haftig** für Missbruuch oder Schade. Bruuch uf eigeni
Verantwortig. S Tool **macht sälber kei Aagriff** und d KI **analysiert nume** – d
Verantwortig für jedi Aktion lit bi dr Person wo s bruucht.

---

## Lizänz

Veröffentlicht under dr [MIT-Lizänz](LICENSE).

---

## Web-Dashboard (optional)

E lokals Lagebild vo dinere Werchstatt im Browser: Severity-Verteilig, Findings,
Hosts/Dienscht, Loot und Notize uf ei Blick.

```bash
pip install -e ".[web]"          # FastAPI + uvicorn
pentos serve                     # startet http://127.0.0.1:8787
pentos serve --port 9000 --project mis-projäkt
```

Im Dashboard chasch dr **Status vo Findings ändere** und **Notize aalege**; d Änderige
lande diräkt im Projäkt. Es bindet standardmässig nume a `127.0.0.1` (**kei offeni
Aagriffsflächi**); Schriibzuegriff sin zuesätzlich mit ere Origin-Prüefig gäge Drive-By
vo fremde Websites gschützt.

---

## MCP-Server (optional)

Macht d PentOS-Werchstatt für MCP-Clients wie **Claude Code** oder **Cursor** abfrogbar.
Du redsch mit dim Projäkt in normaler Sproch („zeig mir d High-Findings", „was stoht in
de Notize zu SMB"). Alli MCP-Tools sin **nume läsend/analysierend**; kei Tool macht
Scans oder Aagriff. S gross Dänke macht dr Client, d Kontrolle bliibt bi dir.

```bash
pip install -e ".[mcp]"
```

Client-Konfiguration (Bischpiel, z.B. in de MCP-Iistellige vom Client):

```json
{ "mcpServers": { "pentos": { "command": "pentos", "args": ["mcp"] } } }
```

Tools wo's git: `pentos_list_projects`, `pentos_summary`, `pentos_findings`,
`pentos_hosts`, `pentos_loot`, `pentos_notes`, `pentos_knowledge`.

---

## Changelog

Alli Versjoone und Änderige stöhn in [`CHANGELOG.md`](CHANGELOG.md).
Aktuelli Versjoon: **2.22.0**.
