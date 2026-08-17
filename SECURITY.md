# Security Policy

> English version below · [Deutsche Version](#sicherheitsrichtlinie)

## Reporting a Vulnerability

Found a security issue in **PentOS itself** (not in a target you scanned with it)?
Please report it privately, not as a public issue:

1. Go to the [Security tab](https://github.com/kaldox/pentos/security) of this repository
2. Click **"Report a vulnerability"** to open a private GitHub Security Advisory
3. Describe the issue: what it is, how to reproduce it, and its impact

You'll get an acknowledgement and, once a fix is ready, credit in the advisory
(unless you'd rather stay anonymous).

## Scope

**In scope** - vulnerabilities in PentOS's own code, e.g.:
- Path traversal / zip-slip in project export or import
- Injection or unsafe deserialization when parsing scan imports or reports
- Anything that lets an untrusted project file, scan result, or report template
  execute unintended code or escape the project's own workspace directory

**Out of scope:**
- Vulnerabilities in third-party tools PentOS wraps (nmap, nikto, nuclei, …) -
  please report those to the respective upstream project
- Findings PentOS *surfaces* while scanning a target - that's the tool doing
  its job, not a PentOS vulnerability

## Supported Versions

Only the latest released version is supported with security fixes. There is
no long-term support branch - always update to the newest release.

## Response

PentOS is a hobby project maintained in spare time, so there's no guaranteed
response time or SLA - but security reports get priority over feature
requests and regular bugs.

---

## Sicherheitsrichtlinie

## Eine Schwachstelle melden

Eine Sicherheitslücke in **PentOS selbst** gefunden (nicht in einem Ziel, das
du damit gescannt hast)? Bitte privat melden, nicht als öffentliches Issue:

1. Zum [Security-Tab](https://github.com/kaldox/pentos/security) dieses Repos gehen
2. **"Report a vulnerability"** klicken - öffnet einen privaten GitHub Security Advisory
3. Beschreiben: was ist das Problem, wie reproduziert man es, welche Auswirkung hat es

Du bekommst eine Rückmeldung und, sobald ein Fix bereitsteht, eine Nennung im
Advisory (falls gewünscht - auch anonym möglich).

## Umfang

**Relevant** - Schwachstellen im eigenen PentOS-Code, z.B.:
- Path-Traversal/Zip-Slip beim Projekt-Export oder -Import
- Injection oder unsichere Deserialisierung beim Einlesen von Scan-Importen
  oder Reports
- Alles, womit eine nicht vertrauenswürdige Projektdatei, ein Scan-Ergebnis
  oder eine Report-Vorlage unbeabsichtigten Code ausführen oder aus dem
  eigenen Projekt-Workspace ausbrechen könnte

**Nicht relevant:**
- Schwachstellen in externen Tools, die PentOS nur aufruft (nmap, nikto,
  nuclei, …) - die bitte beim jeweiligen Projekt melden
- Findings, die PentOS beim Scannen eines Ziels *anzeigt* - das ist das Tool,
  das seinen Job macht, keine PentOS-Schwachstelle

## Unterstützte Versionen

Nur die jeweils aktuellste veröffentlichte Version bekommt Sicherheits-Fixes.
Es gibt keinen Long-Term-Support-Branch - immer auf die neueste Version
aktualisieren.

## Reaktionszeit

PentOS ist ein Hobby-Projekt, gepflegt in der Freizeit - keine garantierte
Reaktionszeit oder SLA, aber Sicherheitsmeldungen haben Vorrang vor
Feature-Wünschen und regulären Bugs.
