"""Shared, contained module importing for the drop-in directories.

Providers, tools, context providers and prompts all load the same way: scan a
directory, import each file, and never let one bad file take down the plugin.
This is the part they share.

The distinction that matters is between an *expected* failure and a real one.
Not having the Anthropic SDK installed is the normal state for someone who does
not use Claude, and it deserves a single line saying which provider is
unavailable and why. A syntax error or an exception raised by a third-party
drop-in is a genuine defect, and there a traceback is the whole point.
"""

import importlib
import importlib.util
import traceback


def _missing_dependency(exc):
    """The dependency name from an import failure, or None if it isn't one."""
    if isinstance(exc, ModuleNotFoundError):
        return exc.name or str(exc)
    if isinstance(exc, ImportError):
        # 'from google import genai' raises ImportError, not ModuleNotFoundError.
        return getattr(exc, "name", None) or str(exc)
    return None


def import_module_file(py_file, kind: str, package: str = None) -> bool:
    """Import one file. Returns True if it loaded.

    ``package`` imports it as a member of that package rather than by path,
    which keeps a single copy of modules that import each other.
    """
    try:
        if package:
            importlib.import_module(f"{package}.{py_file.stem}")
        else:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return True
    except (ImportError, ModuleNotFoundError) as e:
        missing = _missing_dependency(e)
        print(
            f"Gepetto: {kind} '{py_file.stem}' unavailable, optional dependency "
            f"missing: {missing}"
        )
        return False
    except Exception:
        # Unexpected: a broken file, not an absent dependency. Show the trace.
        print(f"Gepetto: failed to load {kind} {py_file}:")
        traceback.print_exc()
        return False


def iter_module_files(folder):
    """Importable files in a directory, skipping dunder and private ones."""
    if not folder.is_dir():
        return []
    return [f for f in sorted(folder.glob("*.py")) if not f.name.startswith("_")]
