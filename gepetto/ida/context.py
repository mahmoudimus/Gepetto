"""Extra prompt context for the hotkey actions.

The CLI can ask for more information with tools, but the Edit > Gepetto hotkeys
(explain, rename variables, comment) build a prompt inline and send it once, so
whatever the model receives is all it will ever see. This is the seam that lets
extra context be added to those prompts without editing the handlers.

A provider is a callable taking the target address and returning a string, or
None to contribute nothing. Register at module scope:

    from gepetto.ida.context import register_context_provider
    register_context_provider(my_provider, name="callers")

Drop files into $IDAUSR/cfg/gepetto/context/ and they load at startup.
"""

import importlib.util
import pathlib
import traceback

from gepetto.loader import import_module_file, iter_module_files

# name -> callable(ea) -> str | None
CONTEXT_PROVIDERS = {}

_current_source = "built-in"
_LOADED_FILES = {}

# Providers are advisory extras, never the main event: a runaway provider must
# not blow up the prompt it is decorating.
MAX_CONTEXT_CHARS = 12000


def register_context_provider(provider, name=None):
    if not callable(provider):
        print(f"Gepetto: ignoring a context provider that is not callable ({_current_source}).")
        return
    key = name or getattr(provider, "__name__", None) or f"provider_{len(CONTEXT_PROVIDERS)}"
    if key in CONTEXT_PROVIDERS and CONTEXT_PROVIDERS[key] is not provider:
        print(f"Gepetto: context provider '{key}' overridden by {_current_source}")
    CONTEXT_PROVIDERS[key] = provider


def gather_context(ea, max_chars=MAX_CONTEXT_CHARS) -> str:
    """Run every provider and join what they return.

    A provider that raises is reported and skipped: extra context is a bonus,
    and losing it must never cost the user the action they actually asked for.
    """
    chunks = []
    budget = max_chars
    for name, provider in CONTEXT_PROVIDERS.items():
        if budget <= 0:
            break
        try:
            produced = provider(ea)
        except Exception:
            print(f"Gepetto: context provider '{name}' failed:")
            traceback.print_exc()
            continue
        if not produced:
            continue
        text = str(produced).strip()
        if not text:
            continue
        if len(text) > budget:
            text = text[:budget] + "\n// ... context truncated ..."
        chunks.append(text)
        budget -= len(text)
    return "\n\n".join(chunks)


def format_extra_context(ea, max_chars=MAX_CONTEXT_CHARS) -> str:
    """gather_context() wrapped in a labelled block, or "" when there is none.

    Returns an empty string rather than a header with nothing under it, so a
    prompt with no registered providers is byte-identical to the old one.
    """
    body = gather_context(ea, max_chars=max_chars)
    if not body:
        return ""
    return (
        "\nAdditional context gathered from the database "
        "(supporting material, not the function under analysis):\n"
        f"{body}\n"
    )


def load_context_directory(folder, source: str):
    global _current_source
    folder = pathlib.Path(folder)
    if not folder.is_dir():
        return
    for py_file in iter_module_files(folder):
        resolved = str(py_file.resolve())
        if resolved in _LOADED_FILES:
            continue
        _current_source = f"{source} ({py_file})"
        if import_module_file(py_file, "context provider"):
            _LOADED_FILES[resolved] = True
    _current_source = "built-in"


def load_available_context_providers():
    import gepetto.paths

    load_context_directory(gepetto.paths.user_dir() / "context", "user")
