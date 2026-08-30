"""A dialog for the settings that were previously file-only.

Most of Gepetto's configuration is set once and forgotten, which is why editing
a file was tolerable. The per-provider knobs are not like that: reasoning
effort and temperature are things you change while working, and a setting you
have to close IDA to reach is a setting nobody uses.

The decisions live here rather than in the form: which settings exist, what
each accepts, what the user actually changed, and what to refuse. The form is
a shell over that, because a modal dialog cannot be tested and the rules can.

Values shown come from the configuration file alone, never from the
environment. get_config falls back to an environment variable when the file
value is empty, so showing the resolved value would mean a save quietly copied
a key out of the environment and into a file on disk.
"""

import json
import re

import gepetto.config

_ = gepetto.config._


#: How a setting is presented, when its kind does not say enough. The kind
#: still decides what is accepted; this only decides what the user is handed.
WIDGET_FOR_KIND = {
    "bool": "choice",
    "choice": "choice",
    "json": "editor",
    "int": "number",
    "float": "number",
    "text": "text",
}


class Setting:
    """One editable option."""

    __slots__ = ("section", "option", "label", "hint", "kind", "choices",
                 "minimum", "maximum", "soft_maximum", "step", "default",
                 "_widget")

    def __init__(self, section, option, label, hint, kind="text",
                 choices=None, minimum=None, maximum=None, step=None,
                 default=None, widget=None, soft_maximum=None):
        self.section = section
        self.option = option
        self.label = label
        self.hint = hint
        self.kind = kind
        self.choices = choices or []
        self.minimum = minimum
        self.maximum = maximum
        # Where the slider stops, when that is not where the value has to.
        # Temperature is the case: a slider past 1 is mostly wasted travel,
        # but a provider that accepts 1.5 should not have it refused.
        self.soft_maximum = soft_maximum
        self.step = step
        self.default = default
        self._widget = widget

    @property
    def key(self):
        """Field name for the form, unique across sections."""
        return f"{self.section}_{self.option}".replace(" ", "_")

    @property
    def widget(self):
        return self._widget or WIDGET_FOR_KIND.get(self.kind, "text")

    def __repr__(self):
        return f"<Setting {self.section}.{self.option}>"


#: Values providers commonly accept. Offered, not enforced: the field stays
#: typeable because each provider decides its own vocabulary.
REASONING_EFFORTS = ["none", "minimal", "low", "medium", "high"]

#: Sections of the configuration file that are not providers.
NON_PROVIDER_SECTIONS = ("Gepetto",)

#: What tells a provider's section apart from any other section a context
#: provider or tool may have added: somewhere to connect, or something to
#: connect with. Naming the exceptions instead would mean this list growing
#: every time a drop-in invented a section of its own.
PROVIDER_MARKERS = ("API_KEY", "BASE_URL", "HOST")


def language_choices():
    """The locales actually installed, so the list cannot name a missing one."""
    return sorted(getattr(gepetto.config, "available_locales", None) or [])


def general_settings():
    """Built per call: the language list depends on what is installed."""
    return [
        Setting("Gepetto", "LANGUAGE", _("Language"),
                _("Blank for English. The list is the locales installed "
                  "alongside Gepetto."),
                kind="choice", choices=language_choices()),
        Setting("Gepetto", "PROXY", _("Proxy"),
                _("http://host:port to route requests through. Blank for none.")),
        Setting("Gepetto", "COMMENT_POSITION", _("Comment position"),
                _("Where generated comments are placed."),
                kind="choice", choices=["above", "side"]),
        Setting("Gepetto", "AUTO_SHOW_STATUS_PANEL", _("Auto-open status panel"),
                _("Focus the status panel when a request starts."), kind="bool"),
    ]


def provider_settings(section):
    """The knobs that belong to one provider."""
    if not section:
        return []
    return [
        Setting(section, "API_KEY", _("API key"),
                _("Blank means the provider's environment variable is used, if set.")),
        Setting(section, "BASE_URL", _("Base URL"),
                _("Redirect requests elsewhere. Blank for the provider's default.")),
        Setting(section, "REASONING_EFFORT", _("Reasoning effort"),
                _("Your provider decides which values it accepts. Blank sends "
                  "nothing at all, which is not the same as none."),
                choices=REASONING_EFFORTS, widget="dropdown"),
        Setting(section, "TEMPERATURE", _("Temperature"),
                _("Sampling temperature. Blank leaves it to the provider. Models "
                  "that reject the parameter are skipped rather than failed."),
                kind="float", minimum=0.0, maximum=2.0, soft_maximum=1.0,
                step=0.01, widget="slider"),
        Setting(section, "EXTRA_OPTIONS", _("Extra options (JSON)"),
                _("A JSON object merged into every request, last, so it can "
                  "override anything above. For parameters Gepetto does not model."),
                kind="json"),
    ]


def provider_sections():
    """Every provider that could be configured, whether or not it is.

    Not list_models(): a provider only registers itself once it is configured,
    and the one you most need to reach in a settings dialog is the one that
    is not yet.
    """
    sections = set()
    parsed = gepetto.config.parsed_ini
    if parsed is not None:
        sections.update(
            section for section in parsed.sections()
            if section not in NON_PROVIDER_SECTIONS
            and any(parsed.has_option(section, marker)
                    for marker in PROVIDER_MARKERS))
    try:
        from gepetto.models.model_manager import list_models

        for model in list_models():
            section = getattr(model, "CONFIG_SECTION", None)
            if section:
                sections.add(section)
    except Exception:
        # A provider that cannot be listed costs its row, not the dialog.
        pass
    return sorted(sections, key=str.lower)


#: The groups both dialogs show, in the order they were registered.
_GROUPS: list = []


def register_settings_group(build):
    """Add a group of settings to both dialogs.

    ``build(provider_section)`` returns ``(title, [Setting, ...])``, or None to
    leave itself out of this dialog -- which is how the provider group excuses
    itself when no provider is selected, rather than the caller knowing to skip
    an empty list.

    It is called each time a dialog opens, not once at import, so a group whose
    contents depend on the configuration stays correct: the language choices
    are the locales currently installed, and the provider list is whatever the
    file currently holds.

    Usable as a decorator. The two groups below are registered through it, so
    this is how the module composes itself and not a side door.
    """
    _GROUPS.append(build)
    return build


@register_settings_group
def _general_group(provider_section=None):
    return _("General"), general_settings()


@register_settings_group
def _provider_group(provider_section=None):
    """Omitted rather than empty: a group with no settings is a blank tab."""
    settings = provider_settings(provider_section)
    if not settings:
        return None
    return _("Provider: {name}").format(name=provider_section), settings


def settings_for(provider_section=None):
    """The groups shown by the dialog IDA draws itself, in order."""
    groups = (build(provider_section) for build in _GROUPS)
    return [group for group in groups if group]


def every_setting(active_section=None):
    """Groups covering everything the Qt dialog can edit.

    Every provider is included, not only the selected one: the dialog builds
    all of them so that switching between providers cannot lose an edit made
    before the switch, and an untouched provider yields no change anyway.
    """
    sections = provider_sections()
    if active_section and active_section not in sections:
        sections.insert(0, active_section)
    # Every registered group except the provider one, which is expanded below:
    # asked for no section it returns None, and this dialog wants all of them.
    groups = [build(None) for build in _GROUPS]
    groups = [group for group in groups if group]
    groups += [(section, provider_settings(section)) for section in sections]
    return groups


# --- describing the form ------------------------------------------------------
#
# IDA's form syntax gives four characters meaning: '#' delimits a hint, '<' and
# '>' delimit a field, and '{' opens a control reference. Only the last has an
# escape. Text reaching a form line has to lose the others or the parser reads
# prose as syntax -- which matters most for the configuration path, since that
# comes from the filesystem rather than from this file.

_FORM_SYNTAX = re.compile(r"[#<>]")


def form_safe(text):
    """Text that can sit in a form line without being read as syntax."""
    collapsed = " ".join(str(text if text is not None else "").split())
    return _FORM_SYNTAX.sub("", collapsed).replace("{", r"\{")


def form_text(groups, config_path=None):
    """The IDA form description for these groups.

    Each field is written the way IDA writes its own: the tooltip goes between
    the '#' delimiters, and nothing else is added after the field's width. The
    Form class also accepts an `hlp` argument that lands in a later slot of the
    same field, but IDA never populates it anywhere in its own code, and prose
    put there carries the colons that separate a field's parts -- 'http://host'
    alone adds two.

    Labels are padded to a common width because Form aligns on the colon and a
    ragged column is harder to read than it needs to be.
    """
    labels = {setting.key: form_safe(setting.label)
              for _title, settings in groups for setting in settings}
    width = max((len(label) for label in labels.values()), default=10)

    lines = [
        "STARTITEM 0",
        "BUTTON YES* " + form_safe(_("Save")),
        "BUTTON CANCEL " + form_safe(_("Cancel")),
        form_safe(_("Gepetto settings")),
        "",
        form_safe(_("Blank means unset. Editing writes to:")),
        form_safe(config_path or ""),
        "",
    ]

    for title, settings in groups:
        lines.append(form_safe(title))
        for setting in settings:
            lines.append(f"<#{form_safe(setting.hint)}#"
                         f"{labels[setting.key].ljust(width)}:{{{setting.key}}}>")
        lines.append("")

    return "\n".join(lines)


# --- reading ------------------------------------------------------------------

def file_value(setting):
    """What the configuration file says, ignoring the environment."""
    parsed = gepetto.config.parsed_ini
    if parsed is None:
        return ""
    try:
        return (parsed.get(setting.section, setting.option) or "").strip()
    except Exception:
        return ""


def current_values(groups):
    return {setting.key: file_value(setting)
            for _title, settings in groups for setting in settings}


# --- validating ---------------------------------------------------------------

_TRUE = ("true", "yes", "on", "1")
_FALSE = ("false", "no", "off", "0")


def validate(setting, raw):
    """(value, error). An empty value always means "unset" and is allowed."""
    text = (raw or "").strip()
    if not text:
        return "", None

    if setting.kind == "bool":
        lowered = text.lower()
        if lowered in _TRUE:
            return "true", None
        if lowered in _FALSE:
            return "false", None
        return None, _("{label}: expected true or false, got {value!r}").format(
            label=setting.label, value=text)

    if setting.kind == "choice":
        for choice in setting.choices:
            # The choice as written, not as typed: a locale folder is fr_FR,
            # and lowercasing what the user picked would name a directory
            # that does not exist.
            if text.lower() == choice.lower():
                return choice, None
        return None, _("{label}: expected one of {choices}, got {value!r}").format(
            label=setting.label, choices=", ".join(setting.choices), value=text)

    if setting.kind in ("int", "float"):
        try:
            number = int(text) if setting.kind == "int" else float(text)
        except ValueError:
            return None, _("{label}: {value!r} is not a number").format(
                label=setting.label, value=text)
        if setting.minimum is not None and number < setting.minimum:
            return None, _("{label}: must be at least {minimum}").format(
                label=setting.label, minimum=setting.minimum)
        if setting.maximum is not None and number > setting.maximum:
            return None, _("{label}: must be at most {maximum}").format(
                label=setting.label, maximum=setting.maximum)
        return str(number), None

    if setting.kind == "json":
        try:
            parsed = json.loads(text)
        except ValueError as e:
            return None, _("{label}: not valid JSON ({error})").format(
                label=setting.label, error=e)
        if not isinstance(parsed, dict):
            return None, _("{label}: must be a JSON object").format(label=setting.label)
        return text, None

    return text, None


def collect_changes(groups, submitted):
    """(changes, errors) for what the user actually altered.

    Only differences are returned. Rewriting an untouched option would be
    harmless for the value but not for the file: an option the user has
    commented out and left for later should stay that way.

    Nothing is written when anything fails to validate. A dialog that saved
    the four settings it understood and dropped the fifth would be worse than
    one that saved none, because the user would not know which.
    """
    changes, errors = [], []
    for _title, settings in groups:
        for setting in settings:
            if setting.key not in submitted:
                continue
            value, error = validate(setting, submitted[setting.key])
            if error:
                errors.append(error)
                continue
            if value != file_value(setting):
                changes.append((setting.section, setting.option, value))
    if errors:
        return [], errors
    return changes, []


def apply_changes(changes):
    """Write them. Returns the ones that failed, with the reason."""
    failed = []
    for section, option, value in changes:
        try:
            gepetto.config.update_config(section, option, value)
        except Exception as e:
            failed.append(f"{section}.{option}: {e}")
    return failed


def describe_changes(changes):
    """A line the user can check against what they thought they typed."""
    if not changes:
        return _("No settings were changed.")
    parts = []
    for section, option, value in changes:
        shown = "(blank)" if not value else ("*" * 8 if "KEY" in option.upper() else value)
        parts.append(f"{section}.{option} = {shown}")
    return _("Saved: {changes}").format(changes="; ".join(parts))
