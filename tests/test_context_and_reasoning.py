import textwrap

import pytest

from gepetto.ida import context


@pytest.fixture(autouse=True)
def clean_providers(monkeypatch):
    monkeypatch.setattr(context, "CONTEXT_PROVIDERS", {})
    monkeypatch.setattr(context, "_current_source", "built-in")
    monkeypatch.setattr(context, "_LOADED_FILES", {})


# --- prompt context ---------------------------------------------------------

def test_no_providers_contributes_nothing():
    assert context.gather_context(0x401000) == ""
    # Empty rather than a bare header, so prompts are unchanged when unused.
    assert context.format_extra_context(0x401000) == ""


def test_registered_providers_are_joined_in_order():
    context.register_context_provider(lambda ea: "first", name="a")
    context.register_context_provider(lambda ea: "second", name="b")
    assert context.gather_context(0x401000) == "first\n\nsecond"


def test_provider_receives_the_address():
    seen = []
    context.register_context_provider(lambda ea: seen.append(ea) or f"ea={ea:#x}", name="a")
    assert "0x401000" in context.gather_context(0x401000)
    assert seen == [0x401000]


def test_providers_returning_nothing_are_skipped():
    context.register_context_provider(lambda ea: None, name="a")
    context.register_context_provider(lambda ea: "   ", name="b")
    context.register_context_provider(lambda ea: "real", name="c")
    assert context.gather_context(0x401000) == "real"


def test_a_failing_provider_does_not_lose_the_others(capsys):
    def explode(ea):
        raise RuntimeError("boom")

    context.register_context_provider(explode, name="bad")
    context.register_context_provider(lambda ea: "survived", name="good")

    assert context.gather_context(0x401000) == "survived"
    assert "bad" in capsys.readouterr().out


def test_context_is_truncated_to_the_budget():
    context.register_context_provider(lambda ea: "x" * 5000, name="big")
    produced = context.gather_context(0x401000, max_chars=100)
    assert produced.startswith("x" * 100)
    assert "truncated" in produced


def test_budget_is_shared_across_providers():
    context.register_context_provider(lambda ea: "a" * 80, name="one")
    context.register_context_provider(lambda ea: "b" * 80, name="two")
    produced = context.gather_context(0x401000, max_chars=100)
    first, second = produced.split("\n\n")
    assert first == "a" * 80
    # The second provider only gets what the first left of the 100-char budget.
    assert second.startswith("b" * 20)
    assert "truncated" in second


def test_format_wraps_content_in_a_labelled_block():
    context.register_context_provider(lambda ea: "some evidence", name="a")
    formatted = context.format_extra_context(0x401000)
    assert "Additional context gathered from the database" in formatted
    assert "some evidence" in formatted


def test_non_callable_providers_are_rejected(capsys):
    context.register_context_provider("not callable", name="a")
    assert context.CONTEXT_PROVIDERS == {}
    assert "not callable" in capsys.readouterr().out


PROVIDER_TEMPLATE = """
    from gepetto.ida.context import register_context_provider

    def provide(ea):
        return "from {name} at %s" % hex(ea)

    register_context_provider(provide, name="{name}")
"""


def test_drop_in_context_providers_are_discovered(tmp_path):
    (tmp_path / "mine.py").write_text(
        textwrap.dedent(PROVIDER_TEMPLATE).format(name="mine"), encoding="utf-8"
    )

    context.load_context_directory(tmp_path, "user")

    assert "mine" in context.CONTEXT_PROVIDERS
    assert "from mine at 0x401000" in context.gather_context(0x401000)


def test_a_broken_drop_in_provider_does_not_abort_the_scan(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("raise RuntimeError('nope')\n", encoding="utf-8")
    (tmp_path / "working.py").write_text(
        textwrap.dedent(PROVIDER_TEMPLATE).format(name="working"), encoding="utf-8"
    )

    context.load_context_directory(tmp_path, "user")

    assert list(context.CONTEXT_PROVIDERS) == ["working"]
    captured = capsys.readouterr()
    assert "broken.py" in captured.out + captured.err


# --- reasoning effort -------------------------------------------------------

class FakeProvider:
    """Exercises GPT._apply_reasoning_options without constructing a client."""

    CONFIG_SECTION = "MyProvider"

    def __init__(self):
        from gepetto.models.openai import GPT

        self._apply = GPT._apply_reasoning_options.__get__(self)


@pytest.fixture()
def provider():
    return FakeProvider()


def test_reasoning_effort_is_injected_from_the_provider_section(provider, monkeypatch):
    import gepetto.config

    monkeypatch.setattr(
        gepetto.config, "get_config",
        lambda section, option, *a, **k: "high" if (section, option) == ("MyProvider", "REASONING_EFFORT") else None,
    )
    assert provider._apply({"tools": []}) == {"tools": [], "reasoning_effort": "high"}


def test_nothing_is_injected_when_unset(provider, monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "get_config", lambda *a, **k: None)
    assert provider._apply({"tools": []}) == {"tools": []}


@pytest.mark.parametrize("value", ["none", "off", "0", "false", "NONE", "  "])
def test_disabling_values_suppress_the_option(provider, monkeypatch, value):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "get_config", lambda *a, **k: value)
    assert "reasoning_effort" not in provider._apply({})


def test_an_explicit_caller_value_wins(provider, monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "get_config", lambda *a, **k: "high")
    assert provider._apply({"reasoning_effort": "low"})["reasoning_effort"] == "low"


def test_the_callers_dict_is_not_mutated(provider, monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "get_config", lambda *a, **k: "medium")
    original = {"tools": []}
    provider._apply(original)
    assert original == {"tools": []}


def test_none_options_are_handled(provider, monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "get_config", lambda *a, **k: "medium")
    assert provider._apply(None) == {"reasoning_effort": "medium"}


def test_each_provider_reads_its_own_section():
    from gepetto.models.openai import GPT
    from gepetto.models.deepseek import DeepSeek
    from gepetto.models.openrouter import OpenRouter
    from gepetto.models.openai_compatible import OpenAICompatible

    assert GPT.CONFIG_SECTION == "OpenAI"
    assert DeepSeek.CONFIG_SECTION == "DeepSeek"
    assert OpenRouter.CONFIG_SECTION == "OpenRouter"
    assert OpenAICompatible.CONFIG_SECTION == "OpenAICompatible"
