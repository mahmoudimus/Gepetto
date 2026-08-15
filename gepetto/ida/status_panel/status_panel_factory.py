from .panel_interface import StatusPanel
from .no_panel import NoStatusPanel

_panel: StatusPanel | None = None


def get_status_panel() -> StatusPanel:
    global _panel
    if _panel is not None:
        return _panel

    # Try to build a Qt one; fall back to null if anything goes wrong.
    try:
        from .qt_panel import _StatusPanelManager
        _panel = _StatusPanelManager()
    except Exception:
        # Keep the fallback ephemeral so a later desktop-ready call can create
        # the real panel after IDA has initialized its Qt bindings.
        return NoStatusPanel()

    return _panel
