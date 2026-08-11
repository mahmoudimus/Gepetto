import textwrap

import pytest

from gepetto.ida.tools import registry


def schema(name, description="A tool."):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": {}},
        },
    }


class FakeToolCall:
    def __init__(self, name, arguments="{}", id="call_1"):
        self.id = id
        self.type = "function"
        self.function = type("fn", (), {"name": name, "arguments": arguments})()


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    monkeypatch.setattr(registry, "TOOL_REGISTRY", {})
    monkeypatch.setattr(registry, "_current_source", "built-in")
    monkeypatch.setattr(registry, "_LOADED_FILES", {})


def test_registered_tool_appears_in_the_schema_list():
    registry.register_tool(schema("do_thing"), lambda tc, messages: None)
    assert registry.tool_schemas() == [schema("do_thing")]


def test_dispatch_routes_to_the_registered_handler():
    seen = []
    registry.register_tool(schema("do_thing"), lambda tc, messages: seen.append((tc, messages)))

    tc = FakeToolCall("do_thing")
    messages = []
    assert registry.dispatch_tool_call(tc, messages) is True
    assert seen == [(tc, messages)]


def test_dispatch_reports_an_unknown_tool_without_raising():
    messages = []
    assert registry.dispatch_tool_call(FakeToolCall("nope"), messages) is False
    assert messages and messages[0]["role"] == "tool"
    assert "nope" in messages[0]["content"]


def test_a_handler_that_raises_becomes_a_tool_error_not_a_crash():
    def explode(tc, messages):
        raise RuntimeError("boom")

    registry.register_tool(schema("bad"), explode)
    messages = []

    assert registry.dispatch_tool_call(FakeToolCall("bad"), messages) is True
    assert messages and messages[0]["role"] == "tool"
    assert "boom" in messages[0]["content"]


def test_later_registration_overrides_an_earlier_one(capsys):
    registry.register_tool(schema("do_thing", "first"), lambda tc, messages: None)
    registry._current_source = "user (mine.py)"
    registry.register_tool(schema("do_thing", "second"), lambda tc, messages: None)

    schemas = registry.tool_schemas()
    assert len(schemas) == 1
    assert schemas[0]["function"]["description"] == "second"
    assert "overridden by user (mine.py)" in capsys.readouterr().out


def test_registration_rejects_malformed_schemas():
    registry.register_tool({"type": "function"}, lambda tc, messages: None)
    registry.register_tool(schema("ok"), "not callable")
    assert registry.tool_schemas() == []


TOOL_TEMPLATE = """
    from gepetto.ida.tools.registry import register_tool
    from gepetto.ida.tools.tools import add_result_to_messages, tool_result_payload

    SCHEMA = {{
        "type": "function",
        "function": {{
            "name": "{name}",
            "description": "Drop-in tool.",
            "parameters": {{"type": "object", "properties": {{}}}},
        }},
    }}

    def handle(tc, messages):
        add_result_to_messages(messages, tc, tool_result_payload({{"from": "{name}"}}))

    register_tool(SCHEMA, handle)
"""


def write_tool(folder, filename, name):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / filename).write_text(
        textwrap.dedent(TOOL_TEMPLATE).format(name=name), encoding="utf-8"
    )


def test_drop_in_directory_tools_are_discovered_and_dispatchable(tmp_path):
    write_tool(tmp_path, "mine.py", "my_tool")

    registry.load_tool_directory(tmp_path, "user")

    assert [s["function"]["name"] for s in registry.tool_schemas()] == ["my_tool"]

    messages = []
    assert registry.dispatch_tool_call(FakeToolCall("my_tool"), messages) is True
    assert '"from": "my_tool"' in messages[0]["content"]


def test_a_broken_drop_in_tool_does_not_abort_the_scan(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("raise RuntimeError('nope')\n", encoding="utf-8")
    write_tool(tmp_path, "working.py", "good_tool")

    registry.load_tool_directory(tmp_path, "user")

    assert [s["function"]["name"] for s in registry.tool_schemas()] == ["good_tool"]
    captured = capsys.readouterr()
    assert "broken.py" in captured.out + captured.err


def test_loading_a_tool_directory_twice_is_idempotent(tmp_path, capsys):
    write_tool(tmp_path, "mine.py", "my_tool")
    registry.load_tool_directory(tmp_path, "user")
    capsys.readouterr()

    registry.load_tool_directory(tmp_path, "user")

    assert len(registry.tool_schemas()) == 1
    assert "overridden" not in capsys.readouterr().out
