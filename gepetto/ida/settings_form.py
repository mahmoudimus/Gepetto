"""Opening the settings dialog, and the fallback drawn by IDA itself.

show_settings prefers the Qt dialog next door; this file keeps the version
written in IDA's form language for an IDA whose Qt cannot be imported.

Kept apart from gepetto.ida.settings on purpose: everything here needs a
running IDA with a GUI and so cannot be tested, and everything that decides
anything lives next door where it can be.
"""

import ida_kernwin

import gepetto.config
from gepetto.ida.settings import (
    apply_changes,
    collect_changes,
    current_values,
    describe_changes,
    every_setting,
    form_text,
    settings_for,
)

_ = gepetto.config._


def _build(groups, values):
    """Form text and controls for these groups.

    The text comes from settings.form_text so that what the dialog describes
    can be checked without a GUI. Only the controls are built here.

    No control is given an `hlp`: the tooltip is already in the form text,
    where IDA's own forms put it, and passing one appends prose to the field
    itself. See settings.form_text.
    """
    controls = {}

    for _title, settings in groups:
        for setting in settings:
            value = values.get(setting.key, "")
            if setting.kind in ("bool", "choice"):
                items = (["true", "false"] if setting.kind == "bool"
                         else list(setting.choices))
                # An unset option has no entry in the list, so it gets one:
                # silently defaulting to the first choice would change the
                # setting just by opening the dialog.
                if value not in items:
                    items = [""] + items
                controls[setting.key] = ida_kernwin.Form.DropdownListControl(
                    items=items, readonly=True,
                    selval=items.index(value) if value in items else 0)
            else:
                controls[setting.key] = ida_kernwin.Form.StringInput(
                    swidth=64, value=value)

    return form_text(groups, gepetto.config.config_path), controls


class SettingsForm(ida_kernwin.Form):
    def __init__(self, groups, values):
        self.groups = groups
        self._keys = [setting.key for _t, settings in groups for setting in settings]
        self._kinds = {setting.key: setting.kind
                       for _t, settings in groups for setting in settings}
        text, controls = _build(groups, values)
        super().__init__(text, controls)

    def submitted(self):
        """What the user left in each field, as text."""
        result = {}
        for key in self._keys:
            control = getattr(self, key)
            if self._kinds[key] in ("bool", "choice"):
                # A dropdown reports an index into the list it was built with.
                items = control.items
                index = control.value
                result[key] = items[index] if 0 <= index < len(items) else ""
            else:
                result[key] = control.value or ""
        return result


def ask_with_form(groups, values):
    """Ask through IDA's form language. None if the user cancelled."""
    form = SettingsForm(groups, values)
    form.Compile()
    try:
        if not form.Execute():
            return None
        return form.submitted()
    finally:
        form.Free()


def _ask(section):
    """Ask however this IDA can. (groups, submitted), or None if cancelled.

    The groups come back with the answers because the two dialogs do not offer
    the same thing: Qt edits every provider at once, behind a dropdown, while
    IDA's form has room for the selected one only. What gets validated has to
    be what was actually shown.

    Qt first: IDA's form parser rejects this form on macOS while accepting the
    identical string on Linux, and the widgets Qt draws are the ones IDA is
    already made of. The form stays as a fallback for an IDA whose Qt cannot
    be imported, which is the only case where nothing else would appear.
    """
    from gepetto.ida import qt

    if qt.available():
        try:
            from gepetto.ida.settings_dialog import ask_settings

            groups = every_setting(section)
            submitted = ask_settings(groups, current_values(groups),
                                     gepetto.config.config_path, section)
            return None if submitted is None else (groups, submitted)
        except Exception as e:
            print(_("Gepetto: the settings dialog failed ({error}); "
                    "falling back to IDA's form.").format(error=e))

    groups = settings_for(section)
    submitted = ask_with_form(groups, current_values(groups))
    return None if submitted is None else (groups, submitted)


def show_settings():
    """Open the dialog. Returns the change summary, or None if cancelled."""
    section = getattr(gepetto.config.model, "CONFIG_SECTION", None)

    asked = _ask(section)
    if asked is None:
        return None
    groups, submitted = asked

    changes, errors = collect_changes(groups, submitted)
    if errors:
        # Nothing was written: collect_changes refuses partial saves.
        ida_kernwin.warning("\n".join([_("Nothing was saved:")] + errors))
        return "\n".join(errors)

    failed = apply_changes(changes)
    summary = describe_changes(changes)
    if failed:
        summary += " " + _("Failed: {failures}").format(failures="; ".join(failed))
    return summary
