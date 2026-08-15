from types import SimpleNamespace
import importlib
import sys
import types


def test_plugin_starts_with_ui_uninitialized():
    from gepetto.ida import ui

    assert ui.GepettoPlugin()._ui_initialized is False


def test_plugin_init_defers_ui_setup_until_the_desktop_is_ready(monkeypatch):
    from gepetto.ida import ui

    scheduled = []
    initialized = []
    registrations = []

    monkeypatch.setattr(ui.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(ui.ida_kernwin, "is_idaq", lambda: True)
    monkeypatch.setattr(ui.idaapi, "register_action", lambda action: registrations.append(action))
    monkeypatch.setattr(ui.idaapi, "attach_action_to_menu", lambda *_args: None)
    monkeypatch.setattr(ui, "run_when_desktop_ready", scheduled.append, raising=False)
    monkeypatch.setattr(ui.GepettoPlugin, "initialize_ui", lambda self: initialized.append(self), raising=False)
    monkeypatch.setattr(ui.GepettoPlugin, "generate_model_select_menu", lambda self: None)
    monkeypatch.setattr(ui.GepettoPlugin, "_register_auto_show_action", lambda self: None)
    monkeypatch.setattr(ui, "ContextMenuHooks", lambda: SimpleNamespace(hook=lambda: None), raising=False)
    monkeypatch.setattr(ui.gepetto.config, "model", "test-model")
    monkeypatch.setattr(ui.gepetto.config, "auto_show_status_panel_enabled", lambda: False)

    plugin = ui.GepettoPlugin()

    assert plugin.init() == ui.idaapi.PLUGIN_KEEP
    assert initialized == []
    assert registrations == []
    assert len(scheduled) == 1

    scheduled[0]()

    assert initialized == [plugin]


def test_importing_ui_does_not_import_status_panel_consumers(monkeypatch):
    module_names = (
        "gepetto.ida.ui",
        "gepetto.ida.handlers",
        "gepetto.ida.comment_handler",
        "gepetto.ida.cli",
        "gepetto.ida.status_panel.qt_panel",
    )
    for module_name in module_names:
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    importlib.import_module("gepetto.ida.ui")

    assert "gepetto.ida.handlers" not in sys.modules
    assert "gepetto.ida.comment_handler" not in sys.modules
    assert "gepetto.ida.cli" not in sys.modules
    assert "gepetto.ida.status_panel.qt_panel" not in sys.modules


def test_status_panel_factory_does_not_cache_an_early_qt_load_failure(monkeypatch):
    from gepetto.ida.status_panel import status_panel_factory as factory

    class LateQtPanel:
        pass

    late_qt_module = types.ModuleType("gepetto.ida.status_panel.qt_panel")
    monkeypatch.setitem(sys.modules, late_qt_module.__name__, late_qt_module)
    monkeypatch.setattr(factory, "_panel", None)

    assert isinstance(factory.get_status_panel(), factory.NoStatusPanel)
    assert factory._panel is None

    late_qt_module._StatusPanelManager = LateQtPanel

    assert isinstance(factory.get_status_panel(), LateQtPanel)


def test_side_panel_actions_are_exposed_in_the_gepetto_menu():
    from gepetto.ida import ui

    assert ui.GepettoPlugin.show_panel_action_name == "gepetto:show_side_panel"
    assert ui.GepettoPlugin.show_panel_menu_path.endswith("Gepetto/Show Side Panel")
    assert ui.GepettoPlugin.hide_panel_action_name == "gepetto:hide_side_panel"
    assert ui.GepettoPlugin.hide_panel_menu_path.endswith("Gepetto/Hide Side Panel")


def test_show_side_panel_action_displays_the_status_panel(monkeypatch):
    from gepetto.ida import ui

    calls = []
    panel = SimpleNamespace(ensure_shown=lambda: calls.append("shown"))
    monkeypatch.setattr(ui, "_get_status_panel", lambda: panel, raising=False)
    monkeypatch.setattr(ui.ida_kernwin, "execute_sync", lambda callback, _flags: callback())

    assert ui.ShowStatusPanelHandler().activate(None) == 1
    assert calls == ["shown"]


def test_hide_side_panel_action_closes_the_status_panel(monkeypatch):
    from gepetto.ida import ui

    calls = []
    panel = SimpleNamespace(close=lambda: calls.append("closed"))
    monkeypatch.setattr(ui, "_get_status_panel", lambda: panel, raising=False)
    monkeypatch.setattr(ui.ida_kernwin, "execute_sync", lambda callback, _flags: callback())

    assert ui.HideStatusPanelHandler().activate(None) == 1
    assert calls == ["closed"]
