"""Per-provider settings: semantic config, provider-owned translation.

The same concept has at least four spellings across providers -- OpenAI's
reasoning_effort, Anthropic's reasoning.effort, DeepSeek's Responses
output_config.effort, DeepSeek's chat thinking.type -- so the config stays
conceptual and each provider translates.
"""

import pytest

from gepetto.models.base import LanguageModel


def make_model(section="MyProvider", translate=None):
    class Provider(LanguageModel):
        CONFIG_SECTION = section

        @staticmethod
        def get_menu_name():
            return "Provider"

        @staticmethod
        def supported_models():
            return ["m"]

        @staticmethod
        def is_configured_properly():
            return True

        def query_model_async(self, query, cb, stream, additional_model_options):
            raise NotImplementedError

    if translate:
        Provider.apply_reasoning_effort = translate
    return Provider()


@pytest.fixture()
def settings(monkeypatch):
    """Drive get_config from a plain dict of (section, option) -> value."""
    values = {}

    import gepetto.config

    monkeypatch.setattr(
        gepetto.config, "get_config",
        lambda section, option, *a, **k: values.get((section, option)),
    )
    return values


def test_nothing_is_sent_when_nothing_is_configured(settings):
    assert make_model().apply_settings({"tools": []}) == {"tools": []}


def test_reasoning_effort_uses_the_chat_completions_spelling_by_default(settings):
    settings[("MyProvider", "REASONING_EFFORT")] = "high"
    assert make_model().apply_settings({})["reasoning_effort"] == "high"


def test_a_provider_can_translate_to_its_own_spelling(settings):
    settings[("MyProvider", "REASONING_EFFORT")] = "low"

    def to_output_config(self, options, effort):
        options["output_config"] = {"effort": effort}

    result = make_model(translate=to_output_config).apply_settings({})
    assert result == {"output_config": {"effort": "low"}}
    assert "reasoning_effort" not in result


def test_each_provider_reads_its_own_section(settings):
    settings[("A", "REASONING_EFFORT")] = "high"
    settings[("B", "REASONING_EFFORT")] = "low"
    assert make_model("A").apply_settings({})["reasoning_effort"] == "high"
    assert make_model("B").apply_settings({})["reasoning_effort"] == "low"


def test_a_provider_with_no_section_reads_nothing(settings):
    settings[("MyProvider", "REASONING_EFFORT")] = "high"
    assert make_model(section=None).apply_settings({}) == {}


@pytest.mark.parametrize("value", ["  ", ""])
def test_an_unset_value_sends_nothing(settings, value):
    # Not the same as off: it means "whatever the provider does by default",
    # and DeepSeek's default is thinking on at high.
    settings[("MyProvider", "REASONING_EFFORT")] = value
    assert "reasoning_effort" not in make_model().apply_settings({})


@pytest.mark.parametrize("value", ["off", "0", "false", "disabled", "none"])
def test_off_is_normalised_to_none_and_handed_to_the_provider(settings, value):
    settings[("MyProvider", "REASONING_EFFORT")] = value

    seen = []

    def capture(self, options, effort):
        seen.append(effort)

    make_model(translate=capture).apply_settings({})
    assert seen == ["none"], seen


def test_chat_completions_omits_the_parameter_for_none(settings):
    # Chat completions has no value meaning "no reasoning", so it is omitted --
    # but a provider that can say it explicitly still receives "none" above.
    settings[("MyProvider", "REASONING_EFFORT")] = "off"
    assert "reasoning_effort" not in make_model().apply_settings({})


def test_an_explicit_caller_value_wins_over_config(settings):
    settings[("MyProvider", "REASONING_EFFORT")] = "high"
    assert make_model().apply_settings({"reasoning_effort": "low"})["reasoning_effort"] == "low"


def test_temperature_is_only_sent_when_configured(settings):
    assert "temperature" not in make_model().apply_settings({})
    settings[("MyProvider", "TEMPERATURE")] = "0.1"
    assert make_model().apply_settings({})["temperature"] == 0.1


def test_a_non_numeric_temperature_is_ignored_with_a_warning(settings, capsys):
    settings[("MyProvider", "TEMPERATURE")] = "warm"
    assert "temperature" not in make_model().apply_settings({})
    assert "not a number" in capsys.readouterr().out


def test_extra_options_are_merged_verbatim(settings):
    settings[("MyProvider", "EXTRA_OPTIONS")] = '{"thinking": {"type": "disabled"}}'
    assert make_model().apply_settings({})["thinking"] == {"type": "disabled"}


def test_extra_options_win_over_the_semantic_settings(settings):
    # The escape hatch is applied last so it can deliberately override.
    settings[("MyProvider", "REASONING_EFFORT")] = "high"
    settings[("MyProvider", "EXTRA_OPTIONS")] = '{"reasoning_effort": "minimal"}'
    assert make_model().apply_settings({})["reasoning_effort"] == "minimal"


def test_malformed_extra_options_are_ignored_with_a_warning(settings, capsys):
    settings[("MyProvider", "EXTRA_OPTIONS")] = "{not json"
    assert make_model().apply_settings({"tools": []}) == {"tools": []}
    assert "not valid JSON" in capsys.readouterr().out


def test_non_object_extra_options_are_ignored_with_a_warning(settings, capsys):
    settings[("MyProvider", "EXTRA_OPTIONS")] = '["a", "list"]'
    assert make_model().apply_settings({}) == {}
    assert "must be a JSON object" in capsys.readouterr().out


def test_the_callers_options_are_not_mutated(settings):
    settings[("MyProvider", "REASONING_EFFORT")] = "high"
    original = {"tools": []}
    make_model().apply_settings(original)
    assert original == {"tools": []}


def test_none_options_are_handled(settings):
    settings[("MyProvider", "TEMPERATURE")] = "0.2"
    assert make_model().apply_settings(None) == {"temperature": 0.2}


def test_the_builtin_providers_declare_their_sections():
    from gepetto.models.openai import GPT
    from gepetto.models.deepseek import DeepSeek
    from gepetto.models.openai_compatible import OpenAICompatible

    assert GPT.CONFIG_SECTION == "OpenAI"
    assert DeepSeek.CONFIG_SECTION == "DeepSeek"
    assert OpenAICompatible.CONFIG_SECTION == "OpenAICompatible"
