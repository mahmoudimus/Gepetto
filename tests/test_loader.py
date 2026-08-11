"""A missing optional dependency is the normal state, not an error.

Someone who does not use Claude will never have the anthropic SDK installed,
and printing a 15-line traceback for each such provider on every IDA start
buries the messages that matter.
"""

import pytest

from gepetto import loader


def write(folder, name, body):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(body, encoding="utf-8")
    return path


def test_missing_dependency_reports_one_line_without_a_traceback(tmp_path, capsys):
    path = write(tmp_path, "needs_sdk.py", "import a_package_that_is_not_installed\n")

    assert loader.import_module_file(path, "provider") is False

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Traceback" not in output, output
    assert output.count("\n") == 1, f"expected a single line, got:\n{output}"
    assert "needs_sdk" in output
    assert "a_package_that_is_not_installed" in output
    assert "optional dependency missing" in output


def test_a_partial_import_is_also_treated_as_a_missing_dependency(tmp_path, capsys):
    # 'from google import genai' raises ImportError, not ModuleNotFoundError.
    path = write(tmp_path, "partial.py", "from json import not_a_real_name\n")

    assert loader.import_module_file(path, "provider") is False

    output = capsys.readouterr().out
    assert "Traceback" not in output
    assert "optional dependency missing" in output


def test_a_real_defect_still_gets_a_traceback(tmp_path, capsys):
    path = write(tmp_path, "broken.py", "raise RuntimeError('boom')\n")

    assert loader.import_module_file(path, "provider") is False

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Traceback" in output, output
    assert "boom" in output
    assert "failed to load provider" in output


def test_a_syntax_error_gets_a_traceback(tmp_path, capsys):
    path = write(tmp_path, "syntax.py", "def broken(:\n")

    assert loader.import_module_file(path, "provider") is False

    captured = capsys.readouterr()
    assert "Traceback" in captured.out + captured.err


def test_a_good_module_loads_quietly(tmp_path, capsys):
    path = write(tmp_path, "fine.py", "VALUE = 1\n")

    assert loader.import_module_file(path, "provider") is True
    assert capsys.readouterr().out == ""


def test_the_kind_appears_in_messages(tmp_path, capsys):
    path = write(tmp_path, "x.py", "import nope_not_installed\n")
    loader.import_module_file(path, "tool")
    assert "tool 'x'" in capsys.readouterr().out


def test_iter_module_files_skips_private_and_missing_directories(tmp_path):
    write(tmp_path, "__init__.py", "")
    write(tmp_path, "_helper.py", "")
    write(tmp_path, "real.py", "")
    write(tmp_path, "notes.txt", "")

    assert [f.name for f in loader.iter_module_files(tmp_path)] == ["real.py"]
    assert loader.iter_module_files(tmp_path / "missing") == []


def test_real_providers_with_absent_sdks_stay_quiet(capsys):
    """The exact case from the report: azure, anthropic and google-genai."""
    import pathlib

    import gepetto.paths
    from gepetto.models import model_manager

    before = dict(model_manager._LOADED_FILES)
    try:
        model_manager._LOADED_FILES.clear()
        model_manager._load_directory(
            gepetto.paths.PLUGIN_DIR / "models", "built-in", package="gepetto.models"
        )
    finally:
        model_manager._LOADED_FILES.clear()
        model_manager._LOADED_FILES.update(before)

    output = capsys.readouterr().out + capsys.readouterr().err
    # Whatever is or is not installed in this environment, absent SDKs must
    # never produce a traceback.
    assert "Traceback" not in output, output
