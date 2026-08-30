"""The controls behind the settings dialog.

Showing the dialog needs a GUI, but building and compiling it does not, and
compiling is where the form string IDA has to parse is actually produced.
"""

import re

import ida_kernwin
import pytest

from gepetto.ida import settings as S
from gepetto.ida import settings_form as SF


@pytest.fixture
def built():
    groups = S.settings_for("DeepSeek")
    values = {setting.key: "" for _t, settings in groups for setting in settings}
    return groups, values, SF._build(groups, values)


def test_a_control_exists_for_every_setting(built):
    groups, _values, (_text, controls) = built
    keys = [setting.key for _t, settings in groups for setting in settings]
    assert sorted(controls) == sorted(keys)


def test_no_control_carries_a_help_string(built):
    # An hlp= lands inside the field itself, after its width, where IDA's own
    # forms leave nothing. Prose there brings the colons that separate a
    # field's parts with it.
    _groups, _values, (_text, controls) = built
    assert [key for key, control in controls.items() if control.hlp is not None] == []


def test_the_choice_settings_became_dropdowns(built):
    _groups, _values, (_text, controls) = built
    assert isinstance(controls["Gepetto_COMMENT_POSITION"],
                      ida_kernwin.Form.DropdownListControl)
    assert isinstance(controls["Gepetto_PROXY"], ida_kernwin.Form.StringInput)


def test_an_unset_choice_gets_a_blank_entry_rather_than_the_first_option():
    groups = S.settings_for(None)
    values = {setting.key: "" for _t, settings in groups for setting in settings}
    _text, controls = SF._build(groups, values)
    # Opening the dialog must not decide the setting for the user.
    assert controls["Gepetto_COMMENT_POSITION"].value == 0


def test_a_set_choice_comes_back_selected():
    groups = S.settings_for(None)
    values = {setting.key: "" for _t, settings in groups for setting in settings}
    values["Gepetto_COMMENT_POSITION"] = "side"
    _text, controls = SF._build(groups, values)
    assert controls["Gepetto_COMMENT_POSITION"].value == 1


# --- what IDA is actually handed -----------------------------------------------

FIELD = re.compile(r"<[^>]*:(?P<tag>[A-Za-z$%][^>]*)>")


def compiled_text(groups, values):
    form = SF.SettingsForm(groups, values)
    form.Compile()
    try:
        return form._Form__args[0].decode("utf-8")
    finally:
        form.Free()


def test_every_compiled_field_has_the_shape_ida_writes_itself(built):
    groups, values, _ = built
    text = compiled_text(groups, values)
    fields = [line for line in text.splitlines() if line.startswith("<")]
    assert len(fields) == 9
    for line in fields:
        # e.g. <#hint#Language              :A11:1024:64::>
        tag = FIELD.search(line).group("tag")
        assert tag.endswith("::"), line
        assert tag.count(":") == 4, line


def test_a_hint_with_a_colon_stays_out_of_the_field(built):
    groups, values, _ = built
    text = compiled_text(groups, values)
    proxy = next(line for line in text.splitlines() if ":A" in line and "Proxy" in line)
    # The hint says http://host:port. Those colons belong before the label,
    # inside the '#' delimiters, and nowhere else.
    assert proxy.split("#")[1].count(":") == 2
    assert FIELD.search(proxy).group("tag").count(":") == 4


# --- which dialog gets used ----------------------------------------------------

def test_qt_reports_honestly_when_it_is_not_there():
    # Headless IDA has no Qt at all, and asking for a main window there must
    # answer None rather than raise.
    from gepetto.ida import qt

    assert qt.available() is (qt.binding is not None)
    if not qt.available():
        assert qt.main_window() is None


def test_without_qt_the_ida_form_is_used(monkeypatch):
    from gepetto.ida import qt

    monkeypatch.setattr(qt, "binding", None)
    asked = []
    monkeypatch.setattr(SF, "ask_with_form", lambda groups, values: asked.append("form"))
    SF._ask(None)
    assert asked == ["form"]


def test_a_broken_qt_dialog_falls_back_rather_than_failing(monkeypatch, capsys):
    import sys
    import types

    from gepetto.ida import qt

    monkeypatch.setattr(qt, "binding", "PySide6")
    broken = types.ModuleType("gepetto.ida.settings_dialog")

    def refuse(*args, **kwargs):
        raise RuntimeError("no display")

    broken.ask_settings = refuse
    monkeypatch.setitem(sys.modules, "gepetto.ida.settings_dialog", broken)

    asked = []
    monkeypatch.setattr(SF, "ask_with_form", lambda groups, values: asked.append("form"))
    SF._ask(None)
    assert asked == ["form"]
    assert "settings dialog failed" in capsys.readouterr().out


def test_cancelling_saves_nothing(monkeypatch):
    monkeypatch.setattr(SF, "_ask", lambda section: None)
    written = []
    monkeypatch.setattr(SF, "apply_changes", lambda changes: written.append(changes))
    assert SF.show_settings() is None
    assert written == []


# --- the Qt binding layer ------------------------------------------------------
#
# Both helpers exist because Qt6 changed how enums are named and combined.
# Neither needs Qt to be present to be checked.

def test_a_scoped_enum_member_is_preferred():
    from gepetto.ida import qt

    class Scope:
        Member = "scoped"

    class Owner:
        Scoped = Scope
        Member = "flat"

    assert qt.enum_value(Owner, "Scoped", "Member") == "scoped"


def test_a_flat_enum_member_is_still_found():
    from gepetto.ida import qt

    class Owner:
        Member = "flat"

    # Qt5 hangs members straight off the class, with no enum type to look in.
    assert qt.enum_value(Owner, "Missing", "Member") == "flat"


def test_flags_combine_as_plain_numbers():
    from gepetto.ida import qt

    assert qt.flag_or(1, 2, 4) == 7
    assert qt.flag_or() == 0


def test_flags_combine_when_the_binding_wraps_them():
    from gepetto.ida import qt

    class Flag(int):
        # Qt6 members will not OR directly; they carry the number in .value.
        @property
        def value(self):
            return int(self)

    combined = qt.flag_or(Flag(2048), Flag(4194304))
    assert int(combined) == 2048 | 4194304
    # And the answer stays in the family it started in, because Qt setters
    # reject a bare integer from the wrong one.
    assert isinstance(combined, Flag)
