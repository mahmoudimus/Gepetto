"""One editor per kind of setting.

Every editor answers the same two questions -- what does it hold, and put this
in it -- as text, because the configuration file is text and gepetto.ida.settings
already knows how to judge a string. Nothing here validates anything; a widget
that decided what was acceptable would be a second opinion to keep in step with
the first.

Each one carries a clear button, because blank is a real value in this file:
it means "unset", which is not the same as zero and not the same as the
default. A slider with no way back to blank would quietly turn every setting
it touches into an explicit one.

Importing this module requires Qt.
"""

import json

import gepetto.config
from gepetto.ida import qt
from gepetto.ida.qt import QtCore, QtGui, QtWidgets


_ = gepetto.config._

CLEAR_GLYPH = "\U0001F6AB"  # 🚫
CLEAR_CODEPOINT = 0x1F6AB
#: Not every desktop has a font with that emoji in it, and a button showing an
#: empty box is worse than one showing a plain cross.
CLEAR_FALLBACK = "✕"  # ✕


def clear_glyph(widget):
    """The clear button's label, if this desktop can draw it."""
    try:
        if QtGui.QFontMetrics(widget.font()).inFontUcs4(CLEAR_CODEPOINT):
            return CLEAR_GLYPH
    except Exception:
        pass
    return CLEAR_FALLBACK


def warning_palette(widget):
    """The widget's own palette, with its text turned to a warning colour.

    Through the palette rather than a stylesheet with a hex value in it: IDA
    is themed, and often dark, so a colour picked here to look right on one
    theme is a colour that is illegible on the other. Which red depends on
    what it is being read against.
    """
    palette = QtGui.QPalette(widget.palette())
    role = qt.enum_value(QtGui.QPalette, "ColorRole", "Window")
    dark = palette.color(role).lightness() < 128
    red = QtGui.QColor("#ff8a80") if dark else QtGui.QColor("#a3271f")
    for group in ("Active", "Inactive", "Disabled"):
        palette.setColor(qt.enum_value(QtGui.QPalette, "ColorGroup", group),
                         qt.enum_value(QtGui.QPalette, "ColorRole", "WindowText"),
                         red)
    return palette

#: A slider is integers, so a float setting is counted in steps of its own.
_UNSET_POSITION = -1


class _Editor(QtWidgets.QWidget):
    """An editor and the button that empties it."""

    def __init__(self, setting, parent=None):
        super().__init__(parent)
        self.setting = setting

        row = QtWidgets.QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        for widget, stretch in self.build():
            row.addWidget(widget, stretch)

        clear = QtWidgets.QToolButton()
        clear.setText(clear_glyph(clear))
        clear.setToolTip(_("Clear this setting"))
        clear.setAutoRaise(True)
        clear.clicked.connect(self.clear)
        row.addWidget(clear)
        self.clear_button = clear

    # Subclasses implement these three.
    def build(self):
        raise NotImplementedError

    def value(self):
        raise NotImplementedError

    def set_value(self, text):
        raise NotImplementedError

    def clear(self):
        self.set_value("")


class TextEditor(_Editor):
    def build(self):
        self.line = QtWidgets.QLineEdit()
        if self.setting.default:
            self.line.setPlaceholderText(str(self.setting.default))
        return [(self.line, 1)]

    def value(self):
        return self.line.text() or ""

    def set_value(self, text):
        self.line.setText(text or "")


class NumberEditor(TextEditor):
    """A line edit that will not accept anything but a number.

    The bounds are still checked on save. A validator can stop a stray letter
    as it is typed, but not a number outside the range, because refusing the
    first digit of a number the user has not finished typing makes the field
    impossible to use.
    """

    def build(self):
        rows = super().build()
        if self.setting.kind == "int":
            validator = QtGui.QIntValidator()
            if self.setting.minimum is not None:
                validator.setBottom(int(self.setting.minimum))
            if self.setting.maximum is not None:
                validator.setTop(int(self.setting.maximum))
        else:
            validator = QtGui.QDoubleValidator()
            if self.setting.minimum is not None:
                validator.setBottom(float(self.setting.minimum))
            if self.setting.maximum is not None:
                validator.setTop(float(self.setting.maximum))
        self.line.setValidator(validator)
        return rows


class DropdownEditor(_Editor):
    """A list of the usual answers.

    Editable when the setting's kind is not `choice`: the values a provider
    accepts for something like reasoning effort are its own business, and a
    closed list would lock out the one that is not on it.
    """

    def build(self):
        self.combo = QtWidgets.QComboBox()
        self.strict = self.setting.kind in ("choice", "bool")
        items = (["true", "false"] if self.setting.kind == "bool"
                 else list(self.setting.choices))
        # Blank first, always: unset has to stay reachable.
        self.combo.addItems([""] + items)
        self.combo.setEditable(not self.strict)
        if not self.strict:
            self.combo.lineEdit().setPlaceholderText(_("not set"))
        return [(self.combo, 1)]

    def value(self):
        return self.combo.currentText() or ""

    def set_value(self, text):
        text = text or ""
        index = self.combo.findText(text)
        if index >= 0:
            self.combo.setCurrentIndex(index)
        elif self.strict:
            self.combo.setCurrentIndex(0)
        else:
            self.combo.setEditText(text)


class RangeEditor(_Editor):
    """A slider, the number it is pointing at, and a way back to unset.

    The slider carries one position below its minimum, which reads as blank.
    Without it there would be no way to say "leave this to the provider" once
    the dialog had been opened, and opening a dialog is not consent to set
    every value in it.
    """

    def build(self):
        setting = self.setting
        self.decimals = 0 if setting.kind == "int" else 2
        self.step = float(setting.step or (1 if setting.kind == "int" else 0.01))
        self.minimum = float(setting.minimum if setting.minimum is not None else 0)
        top = setting.soft_maximum if setting.soft_maximum is not None else setting.maximum
        self.maximum = float(top if top is not None else 1)

        self.slider = QtWidgets.QSlider(
            qt.enum_value(QtCore.Qt, "Orientation", "Horizontal"))
        self.readout = QtWidgets.QLabel()
        self.readout.setMinimumWidth(64)
        self.readout.setAlignment(qt.flag_or(
            qt.enum_value(QtCore.Qt, "AlignmentFlag", "AlignRight"),
            qt.enum_value(QtCore.Qt, "AlignmentFlag", "AlignVCenter")))
        self._rebuild_range()
        self.slider.valueChanged.connect(self._show)
        return [(self.slider, 1), (self.readout, 0)]

    def _rebuild_range(self):
        steps = int(round((self.maximum - self.minimum) / self.step))
        self.slider.setRange(_UNSET_POSITION, steps)
        self.slider.setSingleStep(1)
        self.slider.setPageStep(max(1, steps // 10))

    def _position(self, number):
        return int(round((number - self.minimum) / self.step))

    def _number(self, position):
        return self.minimum + position * self.step

    def _show(self, position):
        if position <= _UNSET_POSITION:
            self.readout.setText(_("not set"))
            self.readout.setEnabled(False)
            return
        self.readout.setEnabled(True)
        self.readout.setText(f"{self._number(position):.{self.decimals}f}")

    def value(self):
        position = self.slider.value()
        if position <= _UNSET_POSITION:
            return ""
        number = self._number(position)
        return str(int(round(number))) if self.decimals == 0 else f"{number:.2f}"

    def set_value(self, text):
        text = (text or "").strip()
        if not text:
            self.slider.setValue(_UNSET_POSITION)
            self._show(_UNSET_POSITION)
            return
        try:
            number = float(text)
        except ValueError:
            self.slider.setValue(_UNSET_POSITION)
            self._show(_UNSET_POSITION)
            return
        # A stored value past the end of the slider widens it rather than
        # being dragged into range: showing 1.0 for a file that says 1.5 is
        # a lie, and saving it would make the lie true.
        if number > self.maximum:
            self.maximum = number
            self._rebuild_range()
        elif number < self.minimum:
            self.minimum = number
            self._rebuild_range()
        self.slider.setValue(self._position(number))
        self._show(self.slider.value())


#: Where a tree row keeps what it is, since the columns only show it.
_ROLE_KIND = 0x0100 + 1
_ROLE_VALUE = 0x0100 + 2

_TYPE_NAMES = {
    dict: "object", list: "array", str: "string", bool: "boolean",
    int: "number", float: "number", type(None): "null",
}


def _type_name(value):
    return _TYPE_NAMES.get(type(value), "string")


def _summary(value):
    """What a container shows on its own row, where the value would go."""
    if isinstance(value, dict):
        return "{ %d }" % len(value)
    return "[ %d ]" % len(value)


class JsonTree(QtWidgets.QTreeWidget):
    """JSON as rows, for the half of editing that is not typing.

    Qt has JSON parsing and it has tree widgets, but nothing that joins them,
    and IDA's trees are its own chooser machinery. So this is the join: three
    columns, the value cell parsed as JSON when it can be and kept as a string
    when it cannot, which is how `true` becomes a boolean and `v1` stays text.

    The text below stays the original. This writes into it on every edit
    rather than holding a second copy, because two editors of one value that
    each believe they are right is how an edit gets lost.
    """

    def __init__(self, on_change, parent=None):
        super().__init__(parent)
        self._on_change = on_change
        self._loading = False
        self.setColumnCount(3)
        self.setHeaderLabels([_("Key"), _("Value"), _("Type")])
        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.header().setStretchLastSection(False)
        self.header().setSectionResizeMode(
            1, qt.enum_value(QtWidgets.QHeaderView, "ResizeMode", "Stretch"))
        self.itemChanged.connect(self._edited)

    # --- filling --------------------------------------------------------------

    def load(self, data):
        self._loading = True
        try:
            self.clear()
            if isinstance(data, dict):
                for key, value in data.items():
                    self.addTopLevelItem(self._row(str(key), value, in_object=True))
            self.expandAll()
        finally:
            self._loading = False

    def _row(self, key, value, in_object):
        item = QtWidgets.QTreeWidgetItem([key, "", _type_name(value)])
        flags = [qt.enum_value(QtCore.Qt, "ItemFlag", name)
                 for name in ("ItemIsEnabled", "ItemIsSelectable")]
        if in_object:
            # An array's index is not a name anybody gets to choose.
            flags.append(qt.enum_value(QtCore.Qt, "ItemFlag", "ItemIsEditable"))

        if isinstance(value, (dict, list)):
            item.setData(0, _ROLE_KIND, "object" if isinstance(value, dict) else "array")
            item.setText(1, _summary(value))
            members = value.items() if isinstance(value, dict) else enumerate(value)
            for child_key, child_value in members:
                item.addChild(self._row(str(child_key), child_value,
                                        in_object=isinstance(value, dict)))
        else:
            item.setData(0, _ROLE_KIND, "value")
            item.setData(1, _ROLE_VALUE, value)
            item.setText(1, value if isinstance(value, str) else json.dumps(value))
            flags.append(qt.enum_value(QtCore.Qt, "ItemFlag", "ItemIsEditable"))

        item.setFlags(qt.flag_or(*flags))
        return item

    # --- reading back ---------------------------------------------------------

    def data(self):
        return {item.text(0): self._value_of(item)
                for item in (self.topLevelItem(i)
                             for i in range(self.topLevelItemCount()))}

    def _value_of(self, item):
        kind = item.data(0, _ROLE_KIND)
        children = [item.child(i) for i in range(item.childCount())]
        if kind == "object":
            return {child.text(0): self._value_of(child) for child in children}
        if kind == "array":
            return [self._value_of(child) for child in children]
        return item.data(1, _ROLE_VALUE)

    def _edited(self, item, column):
        if self._loading:
            return
        if column == 1 and item.data(0, _ROLE_KIND) == "value":
            # Parsed when it parses: typing 0.9 should not leave a string
            # behind. Anything else is what the user meant literally.
            raw = item.text(1)
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw
            self._loading = True
            try:
                item.setData(1, _ROLE_VALUE, value)
                item.setText(2, _type_name(value))
            finally:
                self._loading = False
        self._on_change()

    # --- changing shape -------------------------------------------------------

    def add(self):
        """A key in whatever is selected, or at the top when nothing is."""
        selected = self.selectedItems()
        parent = selected[0] if selected else None
        if parent is not None and parent.data(0, _ROLE_KIND) == "value":
            parent = parent.parent()

        self._loading = True
        try:
            if parent is None:
                item = self._row(self._free_key(None), "", in_object=True)
                self.addTopLevelItem(item)
            elif parent.data(0, _ROLE_KIND) == "array":
                item = self._row(str(parent.childCount()), "", in_object=False)
                parent.addChild(item)
            else:
                item = self._row(self._free_key(parent), "", in_object=True)
                parent.addChild(item)
            item.parent().setExpanded(True) if item.parent() else None
        finally:
            self._loading = False
        self.setCurrentItem(item)
        self.editItem(item, 0)
        self._on_change()

    def _free_key(self, parent):
        siblings = ([parent.child(i).text(0) for i in range(parent.childCount())]
                    if parent is not None
                    else [self.topLevelItem(i).text(0)
                          for i in range(self.topLevelItemCount())])
        name, number = "key", 1
        while name in siblings:
            number += 1
            name = f"key{number}"
        return name

    def remove(self):
        for item in self.selectedItems():
            parent = item.parent()
            if parent is None:
                self.takeTopLevelItem(self.indexOfTopLevelItem(item))
            else:
                parent.removeChild(item)
        self._on_change()


class JsonEditor(_Editor):
    """A text area that says whether what is in it is JSON yet, and a tree.

    Two views of one value, and the text is the one that counts: the tree
    writes into it, never the other way round at the same time. Anything else
    means deciding which of two editors was right about a value the user
    changed in both.
    """

    def build(self):
        column = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        self.text = QtWidgets.QPlainTextEdit()
        self.text.setLineWrapMode(
            qt.enum_value(QtWidgets.QPlainTextEdit, "LineWrapMode", "NoWrap"))
        font = QtGui.QFontDatabase.systemFont(
            qt.enum_value(QtGui.QFontDatabase, "SystemFont", "FixedFont"))
        self.text.setFont(font)
        self.text.setPlaceholderText('{"key": "value"}')

        self.tree = JsonTree(self._tree_edited)
        self._writing = False

        tree_page = QtWidgets.QWidget()
        tree_layout = QtWidgets.QVBoxLayout(tree_page)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        tree_layout.addWidget(self.tree)
        buttons = QtWidgets.QHBoxLayout()
        for label, slot, tip in ((_("Add"), self.tree.add, _("Add a key here")),
                                 (_("Remove"), self.tree.remove,
                                  _("Remove the selected key"))):
            button = QtWidgets.QPushButton(label)
            button.setToolTip(tip)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        buttons.addStretch(1)
        tree_layout.addLayout(buttons)

        self.views = QtWidgets.QTabWidget()
        # Tall enough that the tree shows a few rows without the field
        # taking over the tab it lives in.
        self.views.setFixedHeight(200)
        self.views.addTab(self.text, _("Text"))
        self.views.addTab(tree_page, _("Tree"))
        self.views.currentChanged.connect(self._view_changed)

        self.status = QtWidgets.QLabel()
        status_font = self.status.font()
        status_font.setPointSizeF(max(status_font.pointSizeF() - 1.0, 1.0))
        self.status.setFont(status_font)
        self.status.setWordWrap(True)
        self.status.setPalette(warning_palette(self.status))
        self.status.setVisible(False)

        layout.addWidget(self.views)
        layout.addWidget(self.status)

        self.text.textChanged.connect(self._check)
        self._check()
        return [(column, 1)]

    def _parsed(self):
        """The object the text describes, or None if it does not describe one."""
        raw = self.text.toPlainText().strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _view_changed(self, index):
        """Show the tree what the text currently says.

        Only on the way in. Rebuilding it while somebody types would collapse
        every branch they had opened on each keystroke.
        """
        if self.views.widget(index) is self.text:
            return
        parsed = self._parsed()
        self.tree.setEnabled(parsed is not None)
        if parsed is not None:
            self.tree.load(parsed)

    def _tree_edited(self):
        self._writing = True
        try:
            self.text.setPlainText(json.dumps(self.tree.data(), indent=2))
        finally:
            self._writing = False
        self._check()

    def _complain(self, message):
        """Say what is wrong, or nothing at all.

        Nothing at all is the point. Announcing that valid JSON is valid, and
        naming the keys the tree is already showing, put a second line of
        small text under every field that was fine -- so the one field that
        was not read like all the others.
        """
        self.status.setVisible(bool(message))
        self.status.setText(message or "")

    def _check(self):
        raw = self.text.toPlainText().strip()
        if not raw:
            self._complain("")
            return
        try:
            parsed = json.loads(raw)
        except ValueError as e:
            self._complain(_("Not JSON yet: {error}").format(error=e))
            return
        if not isinstance(parsed, dict):
            self._complain(_("Valid JSON, but it has to be an object."))
            return
        self._complain("")

    def value(self):
        return self.text.toPlainText().strip()

    def set_value(self, text):
        self.text.setPlainText(text or "")
        if self.views.currentWidget() is not self.text:
            self._view_changed(self.views.currentIndex())


EDITORS = {
    "text": TextEditor,
    "number": NumberEditor,
    "choice": DropdownEditor,
    "dropdown": DropdownEditor,
    "slider": RangeEditor,
    "editor": JsonEditor,
}


def editor_for(setting, parent=None):
    return EDITORS.get(setting.widget, TextEditor)(setting, parent)
