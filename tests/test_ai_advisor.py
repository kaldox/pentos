"""Tests für den KI-Advisor (analyze/next) und die Datenschutz-Nachfrage."""
from pentos.ai import AIClient


def test_none_provider_returns_none():
    c = AIClient({"provider": "none"}, language="de")
    assert c.interpret_output("nmap", "22/tcp open ssh") is None
    assert c.next_steps("Host x") is None
    assert c.available() is False


def test_advisor_system_prompt_differs():
    c = AIClient({"provider": "none"}, language="de")
    sharp = c._advisor_system(True).lower()
    soft = c._advisor_system(False).lower()
    # Advisor-Modus ist konkret/taktisch, der andere knapper
    assert "konkret" in sharp or "taktisch" in sharp
    assert sharp != soft
    # Beide betonen: NIE selbst ausführen (Guardrail im Prompt)
    assert "nichts aus" in sharp.lower() or "nie" in sharp.lower()


def test_interpret_output_truncates_long_input(monkeypatch):
    c = AIClient({"provider": "ollama"}, language="de")
    captured = {}

    def fake(system, prompt):
        captured["prompt"] = prompt
        return "ok"

    monkeypatch.setattr(c, "_ask_system", fake)
    long = "A" * 20000
    c.interpret_output("nmap", long, advisor=True)
    # Eingabe wird auf ~6000 Zeichen gekürzt (Prompt bleibt handhabbar)
    assert len(captured["prompt"]) < 8000


def test_local_provider_is_available():
    for p in ("ollama", "lmstudio", "openai"):
        assert AIClient({"provider": p}, language="de").available() is True
