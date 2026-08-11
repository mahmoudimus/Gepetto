import textwrap

import pytest

from gepetto.ida import prompts


@pytest.fixture(autouse=True)
def restore_prompts(monkeypatch):
    monkeypatch.setattr(prompts, "PROMPTS", dict(prompts.PROMPTS))
    monkeypatch.setattr(prompts, "_current_source", "built-in")
    monkeypatch.setattr(prompts, "_LOADED_FILES", {})


BUILT_INS = ["explain", "rename", "comment", "generate_c", "generate_python"]


@pytest.mark.parametrize("name", BUILT_INS)
def test_every_action_has_a_prompt(name):
    assert name in prompts.PROMPTS


@pytest.mark.parametrize("name", BUILT_INS)
def test_prompts_render_with_the_standard_arguments(name):
    rendered = prompts.render(name, code="int main(){}", locale="en_US", extra_context="")
    assert "int main(){}" in rendered
    # No unsubstituted placeholders left behind.
    assert "$code" not in rendered and "$grounding" not in rendered


def test_rename_prompt_carries_the_surrounding_context():
    # The whole point of the rename change: the model must see callers and
    # callees, not just the function body.
    rendered = prompts.render(
        "rename", code="int f(){}", locale="en_US",
        extra_context="// Callers of the function under analysis:\nvoid g(){ f(); }",
    )
    assert "void g(){ f(); }" in rendered


def test_rename_prompt_still_demands_a_bare_json_object():
    rendered = prompts.render("rename", code="x", locale="en_US")
    assert "__function__" in rendered
    assert "JSON object" in rendered
    # Braces are literal under string.Template, so the model is shown {}.
    assert "{}" in rendered


def test_comment_prompt_keeps_its_line_number_contract():
    rendered = prompts.render("comment", code="+ 1: x = 1;", locale="en_US")
    assert "line number" in rendered
    assert "'+'" in rendered


def test_registering_a_prompt_overrides_the_built_in(capsys):
    prompts.register_prompt("rename", "my own wording: $code")
    assert prompts.render("rename", code="abc") == "my own wording: abc"
    assert "overridden" in capsys.readouterr().out


def test_empty_overrides_are_rejected(capsys):
    original = prompts.PROMPTS["rename"]
    prompts.register_prompt("rename", "   ")
    prompts.register_prompt("rename", None)
    assert prompts.PROMPTS["rename"] == original
    assert "ignoring empty prompt" in capsys.readouterr().out


def test_unknown_prompt_names_raise():
    with pytest.raises(KeyError):
        prompts.render("no_such_prompt")


def test_an_unknown_placeholder_is_left_alone_rather_than_raising():
    # safe_substitute: the typo costs that substitution, not the action.
    prompts.register_prompt("rename", "uses $not_a_real_field and $code")
    assert prompts.render("rename", code="x") == "uses $not_a_real_field and x"


def test_literal_braces_need_no_escaping():
    prompts.register_prompt("rename", 'emit {"a": {"b": 1}} for $code')
    assert prompts.render("rename", code="f()") == 'emit {"a": {"b": 1}} for f()'


def test_a_value_containing_braces_or_dollars_is_not_rescanned():
    prompts.register_prompt("rename", "$code")
    assert prompts.render("rename", code="jmp $LN10 { }") == "jmp $LN10 { }"


def test_a_custom_template_may_ignore_placeholders():
    prompts.register_prompt("rename", "just rename things")
    assert prompts.render("rename", code="x", locale="fr_FR", extra_context="ctx") == "just rename things"


PROMPT_FILE = """
    from gepetto.ida.prompts import register_prompt

    register_prompt("rename", "dropped-in rename prompt for $code")
"""


def test_drop_in_prompt_files_are_loaded(tmp_path):
    (tmp_path / "mine.py").write_text(textwrap.dedent(PROMPT_FILE), encoding="utf-8")

    prompts.load_prompt_directory(tmp_path, "user")

    assert prompts.render("rename", code="f()") == "dropped-in rename prompt for f()"


def test_a_broken_prompt_file_does_not_abort_the_scan(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("raise RuntimeError('nope')\n", encoding="utf-8")
    (tmp_path / "working.py").write_text(textwrap.dedent(PROMPT_FILE), encoding="utf-8")

    prompts.load_prompt_directory(tmp_path, "user")

    assert "dropped-in" in prompts.render("rename", code="x")
    captured = capsys.readouterr()
    assert "broken.py" in captured.out + captured.err


def test_rename_prompt_asks_for_justified_names():
    rendered = prompts.render("rename", code="int f(){}", locale="en_US")
    assert '"why"' in rendered
    assert "not a restatement of the name" in rendered
    assert '"name": "parse_config_line"' in rendered
    # The JSON example reaches the model exactly as it should be emitted --
    # no doubled braces to undo, which is the reason for string.Template.
    assert '{"name": "<proposed name>", "why": "<the evidence for it>"}' in rendered
    assert "Return {} if nothing warrants renaming." in rendered
    assert "{{" not in rendered
