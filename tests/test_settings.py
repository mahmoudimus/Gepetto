"""The rules behind the settings dialog.

The dialog itself needs a GUI and cannot be tested; what it decides can be.
The two things worth being strict about are that a bad value is never written,
and that opening the dialog and pressing Save changes nothing on its own.
"""

import configparser
import re

import pytest

from gepetto.ida import settings as S


@pytest.fixture
def config(monkeypatch):
    """A real parsed config the settings module reads through."""
    import gepetto.config

    ini = configparser.RawConfigParser()
    monkeypatch.setattr(gepetto.config, "parsed_ini", ini)

    written = []
    monkeypatch.setattr(gepetto.config, "update_config",
                        lambda section, option, value: written.append((section, option, value)))
    ini.written = written
    return ini


def setting(kind="text", **kwargs):
    return S.Setting("Sec", "OPT", "Label", "hint", kind=kind, **kwargs)


# --- validation ---------------------------------------------------------------

def test_blank_is_always_allowed_and_means_unset():
    for kind in ("text", "bool", "choice", "int", "float", "json"):
        value, error = S.validate(setting(kind, choices=["a"]), "   ")
        assert (value, error) == ("", None), kind


@pytest.mark.parametrize("raw,expected", [
    ("true", "true"), ("YES", "true"), ("1", "true"),
    ("false", "false"), ("Off", "false"), ("0", "false"),
])
def test_booleans_accept_the_spellings_people_use(raw, expected):
    assert S.validate(setting("bool"), raw) == (expected, None)


def test_a_non_boolean_is_refused_by_name():
    value, error = S.validate(setting("bool"), "maybe")
    assert value is None and "expected true or false" in error and "Label" in error


def test_a_choice_outside_the_list_is_refused_and_lists_the_options():
    value, error = S.validate(setting("choice", choices=["above", "side"]), "beneath")
    assert value is None and "above, side" in error


def test_a_choice_is_matched_case_insensitively():
    assert S.validate(setting("choice", choices=["above", "side"]), "ABOVE") == ("above", None)


def test_a_number_must_be_a_number():
    value, error = S.validate(setting("int"), "lots")
    assert value is None and "not a number" in error


def test_a_number_below_the_minimum_is_refused():
    value, error = S.validate(setting("int", minimum=1), "0")
    assert value is None and "at least 1" in error


def test_a_number_above_the_maximum_is_refused():
    value, error = S.validate(setting("float", maximum=2.0), "5")
    assert value is None and "at most 2.0" in error


def test_a_number_inside_the_range_survives():
    assert S.validate(setting("float", minimum=0.0, maximum=2.0), "0.7") == ("0.7", None)


def test_extra_options_must_be_valid_json():
    value, error = S.validate(setting("json"), "{not json}")
    assert value is None and "not valid JSON" in error


def test_extra_options_must_be_an_object_not_a_list():
    # A list merged into request options would fail much later and less clearly.
    value, error = S.validate(setting("json"), '[1, 2]')
    assert value is None and "must be a JSON object" in error


def test_valid_json_is_kept_verbatim():
    assert S.validate(setting("json"), '{"top_k": 5}') == ('{"top_k": 5}', None)


# --- reading ------------------------------------------------------------------

def test_a_value_comes_from_the_file(config):
    config.add_section("Gepetto")
    config.set("Gepetto", "LANGUAGE", "fr_FR")
    assert S.file_value(S.Setting("Gepetto", "LANGUAGE", "l", "h")) == "fr_FR"


def test_a_missing_option_reads_as_blank(config):
    assert S.file_value(S.Setting("Nope", "MISSING", "l", "h")) == ""


def test_the_environment_is_not_consulted(config, monkeypatch):
    # Showing the resolved value would mean saving copies a key out of the
    # environment into a file on disk, which the user never asked for.
    config.add_section("OpenAI")
    config.set("OpenAI", "API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-the-environment")
    assert S.file_value(S.Setting("OpenAI", "API_KEY", "l", "h")) == ""


# --- collecting changes -------------------------------------------------------

def test_opening_and_saving_without_edits_writes_nothing(config):
    config.add_section("Gepetto")
    config.set("Gepetto", "LANGUAGE", "fr_FR")
    groups = [("General", [S.Setting("Gepetto", "LANGUAGE", "l", "h")])]
    changes, errors = S.collect_changes(groups, S.current_values(groups))
    assert changes == [] and errors == []


def test_an_edited_value_is_collected(config):
    config.add_section("Gepetto")
    config.set("Gepetto", "LANGUAGE", "fr_FR")
    groups = [("General", [S.Setting("Gepetto", "LANGUAGE", "l", "h")])]
    changes, errors = S.collect_changes(groups, {"Gepetto_LANGUAGE": "zh_CN"})
    assert changes == [("Gepetto", "LANGUAGE", "zh_CN")] and errors == []


def test_clearing_a_value_is_a_change(config):
    config.add_section("Gepetto")
    config.set("Gepetto", "PROXY", "http://localhost:8080")
    groups = [("General", [S.Setting("Gepetto", "PROXY", "l", "h")])]
    changes, _errors = S.collect_changes(groups, {"Gepetto_PROXY": ""})
    assert changes == [("Gepetto", "PROXY", "")]


def test_one_bad_value_stops_every_write(config):
    # Saving the settings it understood and dropping the rest would leave the
    # user with no idea which half landed.
    groups = [("G", [
        S.Setting("Sec", "GOOD", "Good", "h"),
        S.Setting("Sec", "TEMP", "Temperature", "h", kind="float"),
    ])]
    changes, errors = S.collect_changes(
        groups, {"Sec_GOOD": "fine", "Sec_TEMP": "hot"})
    assert changes == []
    assert len(errors) == 1 and "not a number" in errors[0]


def test_every_bad_value_is_reported_not_just_the_first(config):
    groups = [("G", [
        S.Setting("Sec", "A", "A", "h", kind="int"),
        S.Setting("Sec", "B", "B", "h", kind="json"),
    ])]
    _changes, errors = S.collect_changes(groups, {"Sec_A": "x", "Sec_B": "y"})
    assert len(errors) == 2


def test_a_field_the_form_did_not_return_is_left_alone(config):
    config.add_section("Sec")
    config.set("Sec", "OPT", "kept")
    groups = [("G", [S.Setting("Sec", "OPT", "l", "h")])]
    changes, errors = S.collect_changes(groups, {})
    assert changes == [] and errors == []


# --- applying -----------------------------------------------------------------

def test_applying_writes_each_change(config):
    assert S.apply_changes([("Sec", "A", "1"), ("Sec", "B", "2")]) == []
    assert config.written == [("Sec", "A", "1"), ("Sec", "B", "2")]


def test_a_failed_write_is_reported_not_swallowed(config, monkeypatch):
    import gepetto.config

    def boom(section, option, value):
        raise OSError("read-only file system")

    monkeypatch.setattr(gepetto.config, "update_config", boom)
    failed = S.apply_changes([("Sec", "A", "1")])
    assert len(failed) == 1 and "read-only" in failed[0]


# --- reporting ----------------------------------------------------------------

def test_the_summary_names_what_changed():
    summary = S.describe_changes([("Gepetto", "LANGUAGE", "fr_FR")])
    assert "Gepetto.LANGUAGE = fr_FR" in summary


def test_a_saved_key_is_not_echoed_back(config):
    # The summary is printed to the output window and copied into logs.
    summary = S.describe_changes([("OpenAI", "API_KEY", "sk-secret-value")])
    assert "sk-secret-value" not in summary and "OpenAI.API_KEY" in summary


def test_clearing_a_value_reads_as_blank_not_as_nothing():
    assert "(blank)" in S.describe_changes([("Gepetto", "PROXY", "")])


def test_no_changes_says_so():
    assert "No settings were changed" in S.describe_changes([])


# --- the groups themselves ----------------------------------------------------

def test_the_provider_section_follows_the_selected_model():
    groups = S.settings_for("DeepSeek")
    titles = [title for title, _s in groups]
    assert any("DeepSeek" in title for title in titles)
    options = [s.option for _t, settings in groups for s in settings]
    assert {"API_KEY", "REASONING_EFFORT", "TEMPERATURE", "EXTRA_OPTIONS"} <= set(options)


def test_no_provider_section_still_gives_a_usable_dialog():
    groups = S.settings_for(None)
    assert groups and all(settings for _t, settings in groups)
    assert not any("Provider" in title for title, _s in groups)


def test_field_keys_are_unique_across_sections():
    # Two providers both have API_KEY; a collision would have one overwrite the
    # other silently.
    keys = [s.key for _t, settings in S.settings_for("OpenAI") for s in settings]
    assert len(keys) == len(set(keys))



def field_lines(text):
    return [line for line in text.splitlines() if line.startswith("<")]


FIELD = re.compile(r"^<#(?P<hint>[^#]*)#(?P<label>[^:]*):\{(?P<key>[^}]+)\}>$")


def test_every_field_is_a_hint_a_label_and_a_control():
    text = S.form_text(S.settings_for("DeepSeek"), "/tmp/config.ini")
    lines = field_lines(text)
    assert len(lines) == 9
    for line in lines:
        assert FIELD.match(line), line


def test_nothing_follows_the_control_reference():
    # IDA's Form also takes an hlp= argument, which lands after the field's
    # width inside the same colon-separated field. Every field IDA writes
    # itself leaves that empty, so ours do too.
    for line in field_lines(S.form_text(S.settings_for("DeepSeek"), "/tmp/c.ini")):
        assert line.endswith("}>"), line


def test_a_hint_cannot_close_itself_early():
    setting = S.Setting("Sec", "OPT", "Label", "see #64 for <details>")
    line = field_lines(S.form_text([("Group", [setting])], ""))[0]
    assert FIELD.match(line).group("hint") == "see 64 for details"


def test_a_hint_is_flattened_onto_one_line():
    setting = S.Setting("Sec", "OPT", "Label", "first line\nsecond   line")
    line = field_lines(S.form_text([("Group", [setting])], ""))[0]
    assert FIELD.match(line).group("hint") == "first line second line"


def test_a_brace_in_the_path_is_escaped_not_read_as_a_control():
    # The path comes from the filesystem. An unescaped brace would send IDA
    # looking for a control named after part of somebody's home directory.
    text = S.form_text(S.settings_for(None), "/home/{me}/cfg/config.ini")
    assert r"/home/\{me}/cfg/config.ini" in text


def test_the_path_is_shown_so_the_user_knows_what_save_writes():
    text = S.form_text(S.settings_for(None), "/home/me/cfg/config.ini")
    assert "/home/me/cfg/config.ini" in text


def test_labels_line_up():
    lines = field_lines(S.form_text(S.settings_for("DeepSeek"), ""))
    widths = {len(FIELD.match(line).group("label")) for line in lines}
    assert len(widths) == 1


def test_the_buttons_and_title_come_first():
    text = S.form_text(S.settings_for(None), "")
    head = text.splitlines()[:4]
    assert head[0] == "STARTITEM 0"
    assert head[1].startswith("BUTTON YES*")
    assert head[2].startswith("BUTTON CANCEL")
    assert head[3]


@pytest.mark.parametrize("raw,expected", [
    ("plain", "plain"),
    ("a # b", "a  b"),
    ("<tag>", "tag"),
    ("a\nb", "a b"),
    ("  spaced   out  ", "spaced out"),
    (None, ""),
])
def test_form_safe_removes_what_the_parser_would_read(raw, expected):
    assert S.form_safe(raw) == expected


# --- how a setting is presented -----------------------------------------------
#
# The kind still decides what is accepted; the widget only decides what the
# user is handed. Keeping them apart is what lets temperature be a slider that
# stops at 1 while still accepting the 1.5 some providers take.

def test_a_kind_implies_a_widget():
    assert S.Setting("S", "O", "L", "h", kind="json").widget == "editor"
    assert S.Setting("S", "O", "L", "h", kind="bool").widget == "choice"
    assert S.Setting("S", "O", "L", "h").widget == "text"


def test_a_widget_can_be_asked_for_instead():
    setting = S.Setting("S", "O", "L", "h", kind="int", widget="slider")
    assert setting.widget == "slider"
    assert setting.kind == "int"


def test_the_slider_stops_before_the_value_has_to():
    temperature = next(s for s in S.provider_settings("X") if s.option == "TEMPERATURE")
    assert temperature.soft_maximum == 1.0
    # A provider that takes 1.5 must not have it refused just because the
    # slider ends sooner.
    assert S.validate(temperature, "1.5") == ("1.5", None)
    assert S.validate(temperature, "2.5")[1] is not None




def test_reasoning_effort_offers_values_without_insisting_on_them():
    effort = next(s for s in S.provider_settings("X") if s.option == "REASONING_EFFORT")
    assert effort.widget == "dropdown"
    assert "high" in effort.choices
    # Not kind="choice": each provider decides its own vocabulary.
    assert S.validate(effort, "ultra") == ("ultra", None)


# --- languages ----------------------------------------------------------------

def test_the_language_list_is_the_locales_that_exist(monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "available_locales", {"zh_CN", "fr_FR"})
    assert S.language_choices() == ["fr_FR", "zh_CN"]


def test_a_locale_keeps_its_capitalisation():
    # fr_FR names a directory. fr_fr does not.
    setting = S.Setting("Gepetto", "LANGUAGE", "L", "h", kind="choice",
                        choices=["fr_FR", "zh_CN"])
    assert S.validate(setting, "fr_fr") == ("fr_FR", None)


def test_no_locales_installed_is_not_an_error(monkeypatch):
    import gepetto.config

    monkeypatch.setattr(gepetto.config, "available_locales", None)
    assert S.language_choices() == []


# --- which sections are providers ----------------------------------------------


@pytest.fixture
def only_the_file(monkeypatch):
    """Providers as the configuration file describes them, and nothing else.

    Whatever else the test session has imported may have registered a working
    provider, and provider_sections deliberately unions those in.
    """
    import gepetto.models.model_manager as manager

    monkeypatch.setattr(manager, "list_models", lambda: [])
    return manager


def test_a_section_with_somewhere_to_connect_is_a_provider(config, only_the_file):
    config.add_section("Claude")
    config.set("Claude", "API_KEY", "")
    config.add_section("Ollama")
    config.set("Ollama", "HOST", "http://localhost:11434")
    assert S.provider_sections() == ["Claude", "Ollama"]


def test_a_section_belonging_to_something_else_is_not_a_provider(config, only_the_file):
    # A context provider or tool may keep its own section in the same file.
    config.add_section("CallGraph")
    config.set("CallGraph", "MAX_DEPTH", "3")
    config.add_section("OpenAI")
    config.set("OpenAI", "BASE_URL", "")
    assert S.provider_sections() == ["OpenAI"]


def test_gepetto_is_never_a_provider(config, only_the_file):
    """Named explicitly rather than left to the markers.

    A user who puts an API_KEY in [Gepetto] should not get a provider tab for
    it; every other section is judged by whether it carries a marker.
    """
    config.add_section("Gepetto")
    config.set("Gepetto", "API_KEY", "not really")
    assert S.provider_sections() == []


def test_every_provider_is_editable_not_just_the_selected_one(config):
    config.add_section("Claude")
    config.set("Claude", "API_KEY", "")
    config.add_section("DeepSeek")
    config.set("DeepSeek", "API_KEY", "")

    groups = S.every_setting("DeepSeek")
    titles = [title for title, _s in groups]
    assert titles[0] == "General"
    assert "Claude" in titles and "DeepSeek" in titles
    # Switching provider in the dialog must not be able to lose an edit made
    # before the switch, so every provider's fields exist from the start.
    keys = {s.key for _t, settings in groups for s in settings}
    assert {"Claude_API_KEY", "DeepSeek_API_KEY"} <= keys


def test_the_active_provider_is_included_even_if_the_file_has_no_section(config):
    # A provider loaded from a drop-in that has never been configured.
    assert "Homebrew" in [t for t, _s in S.every_setting("Homebrew")]
