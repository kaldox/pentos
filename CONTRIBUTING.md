# Contributing to PentOS

> English version below · [Deutsche Version](#beitragen-zu-pentos)

Thanks for considering a contribution! PentOS is a hobby project maintained
in spare time, so please be patient with reviews - but contributions are
genuinely welcome.

## Before you start

For anything beyond a small fix, please open an issue first to discuss the
approach - saves everyone rework. For bugs, a minimal reproduction helps a
lot.

## Development setup

```bash
git clone https://github.com/kaldox/pentos.git
cd pentos
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[pdf,web,mcp,tui]"
python -m pytest -q
```

## Workflow

- **One feature/fix = one branch = one PR.** Branch off `main`, e.g.
  `feat/gowitness-parser` or `fix/scope-guard-cidr`.
- **Tests are not optional.** New features need tests; bugfixes need a
  regression test that fails without the fix. Run `python -m pytest -q` and
  `python -m compileall -q pentos tests` before opening a PR - both must be
  clean.
- **External formats/schemas get verified, not guessed.** If your change
  parses a tool's output or an external API's response, check it against
  the real source (the tool's own source code, official docs, or a real
  sample) rather than assuming a shape. Every existing parser in this repo
  follows that rule - new ones should too.
- **Update the docs that changed.** New command → `COMMANDS.md` **and**
  `COMMANDS.en.md`. New feature → a line in `CHANGELOG.md`/`CHANGELOG.en.md`
  and, if it's user-facing, `README.md`/`README.en.md`. Both language
  versions stay in sync - PentOS is German-primary with an English mirror,
  not the other way round.
- **No personal or company data in the codebase.** Comments, examples, and
  commit messages should stay generic - no real names, emails, internal
  hostnames, or credentials, even in test fixtures.

## Commit messages

German, with a type prefix, matching the existing history:

```
feat(parser): strukturierter gowitness-Parser (Screenshot-Automatisierung)
fix(scope): CIDR-Vergleich fuer IPv6 korrigiert
docs(readme): Installationsschritte praezisiert
```

## Safety-relevant code

PentOS's core promise is **local-first, AI never executes anything itself,
nothing runs without an explicit user action**. Changes that touch the
runner layer (`pentos/runners/`), scope guard, or engagement-policy gate
(`pentos/policy.py`) should preserve that: opt-in execution, a scope/policy
check before anything touches the network, and a clear `--force` escape
hatch rather than a silent bypass.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue with the bug report template. Security
vulnerabilities in PentOS itself: see [`SECURITY.md`](SECURITY.md) - please
don't file those as public issues.

## License

By contributing, you agree your contribution is licensed under the project's
[MIT License](LICENSE).

---

## Beitragen zu PentOS

Danke fürs Interesse an einem Beitrag! PentOS ist ein Hobby-Projekt, gepflegt
in der Freizeit - etwas Geduld bei Reviews ist hilfreich, aber Beiträge sind
ausdrücklich willkommen.

## Bevor du startest

Für alles über einen kleinen Fix hinaus: bitte erst ein Issue aufmachen und
den Ansatz besprechen - erspart allen doppelte Arbeit. Bei Bugs hilft eine
minimale Reproduktion sehr.

## Entwicklungsumgebung einrichten

```bash
git clone https://github.com/kaldox/pentos.git
cd pentos
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[pdf,web,mcp,tui]"
python -m pytest -q
```

## Ablauf

- **Ein Feature/Fix = ein Branch = ein PR.** Von `main` abzweigen, z.B.
  `feat/gowitness-parser` oder `fix/scope-guard-cidr`.
- **Tests sind nicht optional.** Neue Features brauchen Tests, Bugfixes einen
  Regressionstest, der ohne den Fix fehlschlägt. Vor jedem PR:
  `python -m pytest -q` und `python -m compileall -q pentos tests` - beide
  müssen sauber durchlaufen.
- **Externe Formate/Schemas werden verifiziert, nicht geraten.** Wenn deine
  Änderung die Ausgabe eines Tools oder die Antwort einer externen API
  parst: gegen die echte Quelle prüfen (Tool-Quellcode, offizielle Doku,
  echtes Beispiel), nicht die Struktur annehmen. Jeder bestehende Parser in
  diesem Repo folgt dieser Regel - neue sollten das auch.
- **Die Doku aktualisieren, die sich ändert.** Neuer Befehl → `COMMANDS.md`
  **und** `COMMANDS.en.md`. Neues Feature → ein Eintrag in
  `CHANGELOG.md`/`CHANGELOG.en.md` und, falls nutzersichtbar,
  `README.md`/`README.en.md`. Beide Sprachversionen bleiben synchron -
  PentOS ist deutsch-primär mit englischem Spiegel, nicht umgekehrt.
- **Keine personen- oder firmenbezogenen Daten im Code.** Kommentare,
  Beispiele und Commit-Messages bleiben generisch - keine echten Namen,
  E-Mails, internen Hostnamen oder Zugangsdaten, auch nicht in Test-Fixtures.

## Commit-Messages

Deutsch, mit Typ-Präfix, wie in der bestehenden Historie:

```
feat(parser): strukturierter gowitness-Parser (Screenshot-Automatisierung)
fix(scope): CIDR-Vergleich fuer IPv6 korrigiert
docs(readme): Installationsschritte praezisiert
```

## Sicherheitsrelevanter Code

Das Kernversprechen von PentOS ist **lokal-first, die KI führt niemals selbst
etwas aus, nichts läuft ohne ausdrückliche Nutzeraktion**. Änderungen am
Runner-Layer (`pentos/runners/`), am Scope-Guard oder am
Engagement-Policy-Gate (`pentos/policy.py`) sollten das erhalten: Opt-in-
Ausführung, eine Scope-/Policy-Prüfung bevor irgendwas das Netzwerk berührt,
und ein klares `--force` als Notausgang statt eines stillen Umgehens.

## Bugs vs. Sicherheitsprobleme melden

Normale Bugs: GitHub-Issue mit der Bug-Report-Vorlage. Sicherheitslücken in
PentOS selbst: siehe [`SECURITY.md`](SECURITY.md) - die bitte nicht als
öffentliches Issue melden.

## Lizenz

Mit einem Beitrag stimmst du zu, dass er unter der
[MIT-Lizenz](LICENSE) des Projekts steht.
