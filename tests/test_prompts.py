from gepetto.ida import prompts


def test_explain_prompt_renders_locale_and_preserves_literal_c_braces():
    code = "if (ready) { return value; }"

    rendered = prompts.get_prompt("explain", locale="en_US", code=code)

    assert "Locale: en_US" in rendered
    assert code in rendered
    assert "$code" not in rendered


def test_rename_prompt_keeps_json_examples_literal_while_substituting_code():
    code = "return $LN10;"

    rendered = prompts.get_prompt("rename", locale="en_US", code=code)

    assert '"__function__"' in rendered
    assert "{{" not in rendered
    assert code in rendered


def test_comment_prompt_renders_the_preformatted_commentable_lines():
    lines = "+ 1: return result;"

    rendered = prompts.get_prompt("comment", locale="en_US", lines=lines)

    assert lines in rendered
    assert "$lines" not in rendered


def test_code_generation_prompts_render_decompiled_code():
    code = "int main(void) { return 0; }"

    assert code in prompts.get_prompt("generate_c", code=code)
    assert code in prompts.get_prompt("generate_python", code=code)
