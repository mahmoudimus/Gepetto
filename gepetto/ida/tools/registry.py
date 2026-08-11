"""Registry of IDA tools the model can call.

Tools used to be wired up in three hand-maintained places: the ``TOOLS`` list,
a 22-arm ``if/elif`` dispatch chain in ``cli.py``, and the imports in this
package's ``__init__``. Adding one meant editing all three, and adding one from
outside the plugin directory was impossible.

This mirrors ``gepetto.models.model_manager``: a tool announces itself by
calling :func:`register_tool` at module scope, built-ins and drop-ins load
through the same path, and a later registration of the same name overrides an
earlier one.
"""

import importlib.util
import json
import pathlib
import traceback

# name -> (schema, handler)
TOOL_REGISTRY = {}

# Where the tool currently being imported came from, for log messages.
_current_source = "built-in"

# Drop-in files already executed, keyed by resolved path, so that loading a
# directory twice is a no-op rather than a re-registration.
_LOADED_FILES = {}


def _tool_name(schema):
    if not isinstance(schema, dict):
        return None
    function = schema.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    return name if isinstance(name, str) and name else None


def register_tool(schema, handler):
    """Register one tool. ``handler`` is called as ``handler(tool_call, messages)``."""
    name = _tool_name(schema)
    if not name:
        print(f"Gepetto: ignoring a tool with no function name in its schema ({_current_source}).")
        return
    if not callable(handler):
        print(f"Gepetto: ignoring tool '{name}': handler is not callable ({_current_source}).")
        return

    if name in TOOL_REGISTRY:
        existing_schema, existing_handler = TOOL_REGISTRY[name]
        if existing_schema is schema and existing_handler is handler:
            return
        print(f"Gepetto: tool '{name}' overridden by {_current_source}")

    TOOL_REGISTRY[name] = (schema, handler)


def tool_schemas():
    """The schemas to hand to the model, in registration order."""
    return [schema for schema, _ in TOOL_REGISTRY.values()]


def dispatch_tool_call(tool_call, messages) -> bool:
    """Run the handler for a tool call. Returns False if the tool is unknown.

    A failure here is reported back to the model as a tool result rather than
    raised: the model can then correct itself, whereas an exception would break
    the whole conversation turn.
    """
    from gepetto.ida.tools.tools import add_result_to_messages, tool_error_payload

    name = getattr(getattr(tool_call, "function", None), "name", None)
    entry = TOOL_REGISTRY.get(name)
    if entry is None:
        add_result_to_messages(
            messages,
            tool_call,
            tool_error_payload(f"Unknown tool '{name}'.", available=sorted(TOOL_REGISTRY)),
        )
        return False

    _, handler = entry
    try:
        handler(tool_call, messages)
    except Exception as e:
        print(f"Gepetto: tool '{name}' failed:")
        traceback.print_exc()
        add_result_to_messages(
            messages, tool_call, tool_error_payload(f"Tool '{name}' failed: {e!r}")
        )
    return True


def load_tool_directory(folder, source: str, package: str = None):
    """Import every tool module in a directory.

    ``package`` is set for the built-ins so they import as the package they
    belong to rather than by file path, which keeps a single copy of each
    module. Third-party files are executed by path and contained individually.
    """
    global _current_source
    folder = pathlib.Path(folder)
    if not folder.is_dir():
        return

    for py_file in sorted(folder.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        resolved = str(py_file.resolve())
        if resolved in _LOADED_FILES:
            continue
        _current_source = f"{source} ({py_file})"
        try:
            if package:
                importlib.import_module(f"{package}.{py_file.stem}")
            else:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            _LOADED_FILES[resolved] = True
        except Exception:
            print(f"Gepetto: failed to load tool {py_file}:")
            traceback.print_exc()

    _current_source = "built-in"


def load_available_tools():
    """Load built-in tools, then any dropped into $IDAUSR/cfg/gepetto/tools."""
    import gepetto.paths

    from gepetto.ida.tools import tools as builtin_tools

    builtin_tools.register_builtin_tools()
    load_tool_directory(gepetto.paths.user_dir() / "tools", "user")
