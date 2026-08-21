"""Regression test for a crash-on-exit race.

GepettoPlugin.generate_model_select_menu() spawns a daemon background thread
that iterates every configured provider/model and calls
idaapi.register_action/attach_action_to_menu via ida_kernwin.execute_sync().
term() used to return without ever signalling or joining that thread, so it
could still be mid-flight -- actively touching kernwin action/menu structures
-- at the exact moment IDA proceeds into its own exit-time teardown
(qexit -> term_database -> flush_buffers), which is a native, unrecoverable
crash rather than a Python exception.

term() must now stop and join the thread before doing anything else, so no
Gepetto-owned thread can ever be racing IDA's own shutdown.
"""

import threading
import time

import pytest


@pytest.fixture()
def plugin_with_refresh_state():
    """A GepettoPlugin with just the menu-refresh threading state set up,
    the way initialize_ui() would, without running the full UI init (which
    needs a live decompiler/desktop)."""
    from gepetto.ida import ui

    plugin = ui.GepettoPlugin()
    plugin._menu_refresh_lock = threading.Lock()
    plugin._menu_refresh_thread = None
    plugin._menu_refresh_pending = False
    plugin._menu_refresh_stop = threading.Event()
    return plugin


def test_stop_menu_refresh_thread_is_a_noop_when_nothing_was_started(plugin_with_refresh_state):
    plugin = plugin_with_refresh_state
    plugin._stop_menu_refresh_thread()  # must not raise


def test_stop_menu_refresh_thread_is_a_noop_before_initialize_ui_ever_ran():
    from gepetto.ida import ui

    plugin = ui.GepettoPlugin()
    plugin._stop_menu_refresh_thread()  # no _menu_refresh_* attributes at all


def test_stop_menu_refresh_thread_signals_and_joins_a_running_thread(plugin_with_refresh_state):
    plugin = plugin_with_refresh_state
    iterations = []

    def loop():
        while not plugin._menu_refresh_stop.is_set():
            iterations.append(1)
            time.sleep(0.01)

    plugin._menu_refresh_thread = threading.Thread(target=loop, daemon=True)
    plugin._menu_refresh_thread.start()
    time.sleep(0.03)  # let it actually get going
    assert plugin._menu_refresh_thread.is_alive()

    plugin._stop_menu_refresh_thread()

    assert plugin._menu_refresh_stop.is_set()
    assert not plugin._menu_refresh_thread.is_alive()
    assert len(iterations) > 0  # sanity: the thread really was running


def test_term_stops_the_menu_refresh_thread_before_returning(monkeypatch, plugin_with_refresh_state):
    """The actual crash scenario: a slow menu-refresh pass (many configured
    providers/models) still running when the plugin is asked to shut down.
    term() must not return while it's still touching kernwin state."""
    from gepetto.ida import ui

    plugin = plugin_with_refresh_state
    plugin._ui_initialized = False  # skip the rest of term()'s teardown, isolate this behavior
    plugin.menu = None

    started = threading.Event()
    still_running_when_term_returns = []

    def slow_do_generate_model_select_menu():
        started.set()
        while not plugin._menu_refresh_stop.is_set():
            time.sleep(0.01)

    plugin._menu_refresh_thread = threading.Thread(
        target=slow_do_generate_model_select_menu, name="GepettoModelMenuRefresh", daemon=True
    )
    plugin._menu_refresh_thread.start()
    assert started.wait(timeout=1.0), "background thread never started"

    plugin.term()

    still_running_when_term_returns.append(plugin._menu_refresh_thread.is_alive())
    assert still_running_when_term_returns == [False]


def test_generate_model_select_menu_loop_exits_promptly_once_stopped(monkeypatch, plugin_with_refresh_state):
    """do_generate_model_select_menu() itself must notice the stop signal
    between providers/models, not just at the top of the outer loop --
    otherwise a large provider list still leaves a long window where term()
    is blocked in join() while the thread keeps calling execute_sync()."""
    from gepetto.ida import ui
    import gepetto.models.model_manager as model_manager

    plugin = plugin_with_refresh_state
    plugin.model_action_map = {}
    monkeypatch.setattr(plugin, "detach_actions", lambda: None)

    call_count = []

    def fake_bind(menu_path, action_name, model_name):
        call_count.append(model_name)
        time.sleep(0.02)

    monkeypatch.setattr(plugin, "bind_model_switch_action", fake_bind)

    class FakeProvider:
        @staticmethod
        def get_menu_name():
            return "Fake"

        @staticmethod
        def supported_models():
            return [f"model-{i}" for i in range(200)]  # a "large provider list"

    monkeypatch.setattr(model_manager, "list_models", lambda: [FakeProvider()])

    plugin.generate_model_select_menu()
    time.sleep(0.05)  # let it start binding a few models
    assert plugin._menu_refresh_thread.is_alive()
    calls_before_stop = len(call_count)
    assert 0 < calls_before_stop < 200, "test setup issue: thread finished before we could stop it"

    plugin._stop_menu_refresh_thread(timeout=2.0)

    assert not plugin._menu_refresh_thread.is_alive()
    # It must have stopped well short of processing all 200 fake models.
    assert len(call_count) < 200
