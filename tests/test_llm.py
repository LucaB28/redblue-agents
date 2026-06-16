from core.llm import LLM, _loads_lenient


def test_llm_disabled_when_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    llm = LLM(use_llm=True)
    assert llm.enabled is False
    assert llm.complete("sys", "hi") is None
    assert llm.complete_json("sys", "hi") is None


def test_llm_disabled_when_use_llm_false(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert LLM(use_llm=False).enabled is False


def test_loads_lenient_plain_json():
    assert _loads_lenient('{"a": 1}') == {"a": 1}


def test_loads_lenient_with_fences():
    assert _loads_lenient('```json\n{"a": 1}\n```') == {"a": 1}


def test_loads_lenient_with_surrounding_text():
    assert _loads_lenient('Here is the plan: {"plan": ["x"]} done') == {"plan": ["x"]}


def test_loads_lenient_invalid_returns_none():
    assert _loads_lenient("not json at all") is None
