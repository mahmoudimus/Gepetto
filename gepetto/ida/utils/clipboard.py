"""Clipboard access, across the Qt bindings IDA ships.

IDA 9.2+ carries PySide6 and older versions PyQt5; qt_compat already picks
between them for the status panel, so this reuses that rather than importing a
binding directly.
"""


def copy_to_clipboard(text: str) -> bool:
    """Put text on the system clipboard. Returns False if that was not possible.

    Failing to reach Qt is reported rather than raised: not being able to copy
    should cost the user the copy, not the action they invoked.
    """
    try:
        from gepetto.ida.status_panel.qt_compat import QtWidgets
    except Exception as e:
        print(f"Gepetto: no Qt binding available for clipboard access ({e!r}).")
        return False

    try:
        application = QtWidgets.QApplication.instance()
        if application is None:
            print("Gepetto: no running Qt application; cannot reach the clipboard.")
            return False
        application.clipboard().setText(text)
        return True
    except Exception as e:
        print(f"Gepetto: could not write to the clipboard ({e!r}).")
        return False
