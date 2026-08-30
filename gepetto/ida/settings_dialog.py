"""The settings dialog, built from Qt widgets.

IDA's own form language would be the portable choice, and Gepetto used it, but
its parser rejects this form on macOS while accepting the identical string on
Linux -- the same bytes, IDA 9.4 in both cases. Qt is what IDA's GUI is drawn
with anyway, so the widgets are already loaded.

Nothing here decides anything: which settings exist, what each accepts, and
what counts as a change all still live in gepetto.ida.settings, where they can
be tested without a GUI. This module lays them out and reports back what the
user typed.

Importing it requires Qt. Callers check gepetto.ida.qt.available() first.
"""

import gepetto.config
from gepetto.ida import qt
from gepetto.ida.qt import QtCore, QtWidgets
from gepetto.ida.settings import NON_PROVIDER_SECTIONS, collect_changes
from gepetto.ida.settings_widgets import editor_for


_ = gepetto.config._

DRAWER_MS = 160


class Drawer(QtWidgets.QWidget):
    """A panel that slides open under the thing that chose it.

    One page per provider, all built up front. Building them lazily would
    mean a provider edited and then switched away from had nowhere to keep
    what was typed until Save.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.stack = QtWidgets.QStackedWidget()
        layout.addWidget(self.stack)
        self.setMaximumHeight(0)
        self._animation = QtCore.QPropertyAnimation(self, b"maximumHeight")
        self._animation.setDuration(DRAWER_MS)
        self._animation.setEasingCurve(
            qt.enum_value(QtCore.QEasingCurve, "Type", "InOutCubic"))

    def add_page(self, widget):
        self.stack.addWidget(widget)

    def show_page(self, index, animate=True):
        if index < 0 or index >= self.stack.count():
            return
        self.stack.setCurrentIndex(index)
        target = self.stack.currentWidget().sizeHint().height()
        if not animate:
            self.setMaximumHeight(target)
            return
        self._animation.stop()
        self._animation.setStartValue(self.maximumHeight())
        self._animation.setEndValue(target)
        self._animation.start()


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, groups, values, config_path=None, active_section=None,
                 parent=None):
        super().__init__(parent)
        self.groups = groups
        self.changes = []
        self._editors = {}

        self.setWindowTitle(_("Gepetto settings"))
        self.setMinimumSize(660, 560)

        # Split by what a group holds, not by its title: a translated title is
        # not something to branch on, and the editors have to be built from
        # the same Setting objects that will judge them on save.
        general, providers, analysis = [], [], []
        for title, settings in groups:
            if not settings:
                continue
            section = settings[0].section
            if section == "Gepetto":
                general += settings
            elif section == "Analysis":
                analysis += settings
            elif section not in NON_PROVIDER_SECTIONS:
                providers.append((title, settings))

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self._preamble(config_path))

        tabs = QtWidgets.QTabWidget()
        tabs.addTab(self._page(general, values), _("General"))
        tabs.addTab(self._providers_tab(providers, values, active_section),
                    _("Providers"))
        tabs.addTab(self._page(analysis, values), _("Analysis"))
        layout.addWidget(tabs, 1)

        layout.addWidget(self._buttons())

    # --- building -------------------------------------------------------------

    def _preamble(self, config_path):
        text = _("Blank means unset. Editing writes to:")
        label = QtWidgets.QLabel(f"{text}\n{config_path or ''}")
        label.setWordWrap(True)
        # The path is worth copying; a label nobody can select is worth less.
        label.setTextInteractionFlags(qt.TEXT_SELECTABLE)
        return label

    def _form(self, settings, values):
        """A form of rows, one editor and one hint each."""
        page = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(page)
        form.setFieldGrowthPolicy(qt.enum_value(
            QtWidgets.QFormLayout, "FieldGrowthPolicy", "AllNonFixedFieldsGrow"))
        for setting in settings:
            editor = editor_for(setting)
            editor.set_value(values.get(setting.key, ""))
            self._editors[setting.key] = editor
            label = QtWidgets.QLabel(setting.label)
            label.setToolTip(setting.hint)
            editor.setToolTip(setting.hint)
            form.addRow(label, editor)
            form.addRow(self._hint(setting.hint))
        return page

    def _page(self, settings, values):
        """A form in a scroll area, for a tab that is only settings."""
        area = QtWidgets.QScrollArea()
        area.setWidget(self._form(settings, values))
        area.setWidgetResizable(True)
        area.setFrameShape(qt.enum_value(QtWidgets.QFrame, "Shape", "NoFrame"))
        return area

    def _providers_tab(self, providers, values, active_section):
        """One dropdown, and a drawer holding the chosen provider's settings."""
        page = QtWidgets.QWidget()
        column = QtWidgets.QVBoxLayout(page)

        sections = [name for name, _settings in providers]

        chooser = QtWidgets.QHBoxLayout()
        chooser.addWidget(QtWidgets.QLabel(_("Provider")))
        self.provider = QtWidgets.QComboBox()
        self.provider.addItems(sections)
        chooser.addWidget(self.provider, 1)
        column.addLayout(chooser)

        note = QtWidgets.QLabel(
            _("Every provider is saved, not just this one. A provider with no "
              "key set here falls back to its environment variable."))
        note.setWordWrap(True)
        note.setEnabled(False)
        column.addWidget(note)

        self.drawer = Drawer()
        for section, settings in providers:
            box = QtWidgets.QGroupBox(section)
            inner = QtWidgets.QVBoxLayout(box)
            inner.setContentsMargins(8, 8, 8, 8)
            inner.addWidget(self._form(settings, values))
            self.drawer.add_page(box)
        column.addWidget(self.drawer)
        column.addStretch(1)

        self.provider.currentIndexChanged.connect(self.drawer.show_page)
        if sections:
            start = sections.index(active_section) if active_section in sections else 0
            self.provider.setCurrentIndex(start)
            self.drawer.show_page(start, animate=False)
        return page

    def _hint(self, hint):
        """The hint, shown rather than hidden in a tooltip.

        A setting whose meaning is only discoverable by hovering is a setting
        people guess at.
        """
        label = QtWidgets.QLabel(hint)
        label.setWordWrap(True)
        label.setEnabled(False)
        font = label.font()
        font.setPointSizeF(max(font.pointSizeF() - 1.0, 1.0))
        label.setFont(font)
        return label

    def _buttons(self):
        standard = QtWidgets.QDialogButtonBox
        save = qt.enum_value(standard, "StandardButton", "Save")
        cancel = qt.enum_value(standard, "StandardButton", "Cancel")
        buttons = standard(qt.flag_or(save, cancel))
        # Translated, because IDA's own buttons are and a half-English dialog
        # reads as a bug.
        buttons.button(save).setText(_("Save"))
        buttons.button(cancel).setText(_("Cancel"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        return buttons

    # --- reading back ---------------------------------------------------------

    def submitted(self):
        """What the user left in each field, as text."""
        return {key: editor.value() for key, editor in self._editors.items()}

    def accept(self):
        """Refuse to close on a value that would not be written.

        collect_changes writes nothing when anything fails to validate, so
        closing here would throw away every other edit the user made.
        """
        changes, errors = collect_changes(self.groups, self.submitted())
        if errors:
            QtWidgets.QMessageBox.warning(
                self, _("Gepetto settings"),
                "\n".join([_("Nothing was saved:")] + errors))
            return
        self.changes = changes
        super().accept()


def ask_settings(groups, values, config_path=None, active_section=None):
    """Show the dialog. Returns what the user typed, or None if cancelled."""
    dialog = SettingsDialog(groups, values, config_path, active_section,
                            parent=qt.main_window())
    try:
        # exec_ rather than exec: Qt6 renamed it, and gepetto.ida.qt puts the
        # old name back so this reads the same on both bindings.
        if not dialog.exec_():
            return None
        return dialog.submitted()
    finally:
        dialog.deleteLater()
