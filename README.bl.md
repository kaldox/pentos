# PentOS

[🇩🇪 Deutsch](README.md) · [🇬🇧 English](README.en.md) · **🐻 Baseldütsch**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.17.0%2Brunner-informational)

> ⚠️ **Experimentell:** Die Versjoon isch uf Baseldütsch gschriibe – churzwiilig gmeint, nid zwingend perfekt. Wär e Fähler findet, derf ne gärn flicke.

**E Pentest-Werchstatt, kei Scanner-Sammlig**

PentOS isch **kei Huffe Scanner**, sondern e ganzi Pentest-*Werchstatt*: Findings,
Aagriffspfäd, Notize, Bewiis, Wüsse und Dokumentation stöhn im Zentrum. Lokal-first,
kei Cloud-Zwang, dütschi Uusgaab. D KI isch nume zum Lärne und Analysiere doo –
**si macht sälber nie en Aagriff oder e Befähl**.

> Für autorisierts Teste: CTF, TryHackMe und Engagements wo unterschriibe sin.

---

## Was Phase 1 scho cha

| Aaforderig | Status |
|---|---|
| Pentest-Werchstatt (ganzi Ornerstruktur pro Projäkt) | ✅ |
| Automatischi Notize (z.B. `notes/nmap.md` bim Importiere) | ✅ |
| Pentest-Journal (jedi Aktion mit Ziitstämpel) | ✅ |
| Uufgabe-Sischtem (auto pro Dienscht, Offe/Am Schaffe/Fertig) | ✅ |
| Gschiidi nächschti Schritt (Vorschläg, **kei Uusfüehrig**) | ✅ |
| Automatischi Findings (rägelbasiert, list NSE-Output uus) | ✅ |
| Aagriffspfad-Graph (Mermaid + Graphviz-DOT) | ✅ |
| Obsidian-Integration (Vault mit `[[Wikilinks]]`) | ✅ |
| Loot-Verwaltig (Credentials/Hashes/Tokens/…) | ✅ |
| Bewiis-Verwaltig (Date/Screenshots/Outputs zuen eme Finding) | ✅ |
| CTF/THM-Wüssensdatebank (taggti Iiträg) | ✅ |
| KI-Mentor (Findings erkläre, Enumeration-Ideä; Offline-Fallback) | ✅ |
| Reporting (Markdown uus Findings/Journal/Tasks/Aagriffspfad) | ✅ |
| nmap-XML-Import (Hosts/Dienscht/Scripts) | ✅ |

**Roadmap (nächschti Phase):**
- **Opt-in Runner-Layer:** ✅ druss – Tools laufe uf Wunsch, dr Output wird gläse
  und in d Werchstatt übernoo (Scope-Guard inklusiv).
- **Phase 2:** Methodik-/Playbook-Bibliothek (Web/AD/Linux/Windows als Checkliste),
  besseri Screenshots, Wüssensdatebank uusboue.
- **Phase 3:** KI-Lärnkarte & Notize-Zämmefassige, Nuclei-Templates,
  meh Parser für wiitri Tools, HTML-/PDF-Report.

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
# 1) Projäkt-Werchstatt aalege (wird automatisch aktiv)
pentos project new THM_Alfred

# 2) nmap-Scan importiere  (empfohle: nmap -sC -sV -oX scan.xml <ziil>)
pentos scan import-nmap scan.xml
pentos scan import-scanner report.nessus          # Nessus/OpenVAS/Burp (automatisch erkennt)
#   -> Hosts + Dienscht + Auto-Uufgabe + Auto-Findings + Auto-Notiz

# 3) Überblick
pentos dashboard                   # Projäkt-Übersicht uf ei Blick
pentos finding list
pentos task list
pentos service list

# 4) Nächschti Schritt für e Dienscht (nume Vorschlag)
pentos recommend 4                 # optional: --create-tasks

# 5) Schaffe dokumentiere
pentos task start 12
pentos task done 12
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./screenshots/smb_share.png --kind screenshot --finding 4

# 6) Visualisiere & exportiere
pentos graph mermaid --out attack_paths/ap.mmd
pentos obsidian                                # Vault under <projäkt>/obsidian
pentos report                                  # Markdown-Report
pentos report --pdf                            # PDF (bruucht reportlab)

# 7) KI-Mentor (lokal; ohni Modäll -> Offline-Fallback)
pentos ai explain-finding 4
pentos ai enum 4
```

---

## Runner-Layer (opt-in)

PentOS cha Tools au **sälber laufe loo** – aber nume wenn du si extra startsch.
Dr rohi Output landet in `scans/`, wird gläse und automatisch in
Findings/Tasks/Evidence/Notize gschoba und im Journal protokolliert.

```bash
pentos tools                         # verfüegbari Tools + Installations-Check
pentos run nmap 10.10.10.10          # ganzi Cascade: Hosts/Dienscht/Tasks/Findings
pentos run nmap 10.10.10.10 --dry-run          # nume s Kommando zeige
pentos runs                          # Gschicht vo alle Läuf
```

> **Shell-Modus (`--shell`)**: Standardmässig laufe Tools ohni Shell (fescht `argv`,
> kei Metazeiche-Eval – Injection-Schutz). Mängi Tools bruuche aber e richtigi Shell.
> `--shell` macht das bewusst aa. **Nume mit vertrouewürdige Iigaab bruuche.**

### Sweep – gfüehrti Recon-/Enum-Chetti

`sweep` nimmt e Ziil, startet d Basis-Recon (nmap) und schlat denn pro gfundene
Dienscht di nächschte Tools vor. Rägelbasiert und nochvollziehbar – **kei autonome
Agent**: sicheri Tools chönne automatisch laufe (mit Nochfrog pro Schritt),
Brute-Force/Exploits wärde **nie** automatisch gmacht, nume vorgschlage.

```bash
pentos sweep 10.10.10.10                 # Vorschau: Chetti als fertigi Kommandos
pentos sweep 10.10.10.10 --run           # sicheri Enum-Tools laufe loo
```

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
