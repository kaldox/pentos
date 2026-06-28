"""Tests für den KI-Ausbau (2.27.0): Modellwahl, Fallback, Streaming-Filter,
System-Prompt-Zusammenbau, Sprachsteuerung. Kein Netzwerk nötig."""
from pentos.ai import AIClient, _ThinkStream, _match_installed, LANGUAGES, TASK_PREFS


def _client(**ai):
    base = {"provider": "ollama", "model": "llama3.1", "base_url": "http://x"}
    base.update(ai)
    c = AIClient(base)
    c._installed_cache = ai.pop("_installed", ["deepseek-r1:14b", "gemma3:12b",
                                              "llama3.1:8b", "qwen3-vl:4b", "qwen3:8b"])
    return c


def test_explicit_per_task_model_wins():
    c = _client(models={"analyze": "deepseek-r1:14b"}, auto_model=True)
    assert c.select_model("analyze") == "deepseek-r1:14b"


def test_auto_model_picks_first_installed():
    c = _client(auto_model=True)
    # explain bevorzugt gemma3:12b (installiert)
    assert c.select_model("explain") == "gemma3:12b"


def test_vision_model_used_for_vision_task():
    c = _client(vision_model="qwen3-vl:4b")
    assert c.select_model("vision") == "qwen3-vl:4b"


def test_fallback_chain_order():
    c = _client(auto_model=True)
    cands = c.candidates("ask")
    # default-Modell hängt hinten dran, Auto-Treffer vorne, keine Duplikate
    assert cands[0] == "llama3.1:8b"
    assert "llama3.1" in cands
    assert len(cands) == len(set(cands))


def test_auto_model_off_uses_default():
    c = _client(auto_model=False)
    assert c.select_model("analyze") == "llama3.1"


def test_match_installed_prefix():
    inst = ["deepseek-r1:14b", "gemma3:12b"]
    assert _match_installed("deepseek-r1", inst) == "deepseek-r1:14b"
    assert _match_installed("llava", inst) is None


def test_system_prompt_assembles_persona_language_verbosity():
    c = _client(persona="knapper OSCP-Mentor", language="en",
                verbosity="concise", keep_terms=True)
    sys = c._system("BASIS.")
    assert "BASIS." in sys
    assert "knapper OSCP-Mentor" in sys
    assert "English" in sys
    assert "Original" in sys           # keep_terms-Klausel
    assert "kurz" in sys               # concise


def test_language_clause_uses_display_name():
    c = _client(language="ja")
    assert LANGUAGES["ja"] in c._lang_clause()


def test_keep_terms_off_omits_clause():
    c = _client(language="de", keep_terms=False)
    assert "Original" not in c._lang_clause()


def test_think_stream_filters_split_tags():
    f = _ThinkStream()
    out = "".join(f.feed(p) for p in ["Antwort ", "<th", "ink>reason", "ing</thi", "nk> Ende"])
    assert "reasoning" not in out
    assert "Antwort " in out and "Ende" in out


def test_think_stream_passthrough_without_tags():
    f = _ThinkStream()
    out = "".join(f.feed(p) for p in ["Hallo ", "Welt"])
    assert out == "Hallo Welt"


def test_provider_none_returns_none():
    c = AIClient({"provider": "none"})
    assert c._chat("base", "frage", task="ask") is None
