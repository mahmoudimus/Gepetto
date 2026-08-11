"""Prompt templates for the hotkey actions.

The prompts used to be f-strings buried in the handlers, so improving one meant
editing plugin source that an upgrade overwrites, and comparing two wordings
meant a code change. They live here as named templates, and a user can replace
any of them from $IDAUSR/cfg/gepetto/prompts without touching the plugin:

    from gepetto.ida.prompts import register_prompt
    register_prompt("rename", '''...my wording, {code} ...''')

Templates are formatted with str.format, so literal braces must be doubled.
Every template is passed the same keyword arguments; unused ones are ignored,
which means a custom template can drop a placeholder without breaking.
"""

import importlib.util
import pathlib
import traceback

from gepetto.loader import import_module_file, iter_module_files

PROMPTS = {}

_current_source = "built-in"
_LOADED_FILES = {}


def register_prompt(name, template):
    if not isinstance(template, str) or not template.strip():
        print(f"Gepetto: ignoring empty prompt '{name}' ({_current_source}).")
        return
    if name in PROMPTS and PROMPTS[name] != template:
        print(f"Gepetto: prompt '{name}' overridden by {_current_source}")
    PROMPTS[name] = template


def get_prompt(name, **kwargs) -> str:
    """Render a registered prompt.

    A bad placeholder in a user-supplied template returns the unformatted text
    with a warning rather than raising: a broken prompt should degrade the
    request, not cancel the action the user asked for.
    """
    template = PROMPTS.get(name)
    if template is None:
        raise KeyError(f"No prompt registered under {name!r}")
    try:
        return template.format(**kwargs)
    except Exception as e:
        print(f"Gepetto: prompt '{name}' could not be formatted ({e!r}); sending it unformatted.")
        return template


def load_prompt_directory(folder, source: str):
    global _current_source
    folder = pathlib.Path(folder)
    if not folder.is_dir():
        return
    for py_file in iter_module_files(folder):
        resolved = str(py_file.resolve())
        if resolved in _LOADED_FILES:
            continue
        _current_source = f"user ({py_file})"
        if import_module_file(py_file, "prompt file"):
            _LOADED_FILES[resolved] = True
    _current_source = "built-in"


def load_available_prompts():
    import gepetto.paths

    load_prompt_directory(gepetto.paths.user_dir() / "prompts", "user")


# ---------------------------------------------------------------------------
# Built-in templates.
#
# Shared conventions, adapted from what AiDA (MIT) gets right in its
# BASE_PROMPT: state the role, forbid invention, and demand the bare answer in
# the requested shape with no conversational padding. Kept domain-neutral --
# AiDA targets C++ game binaries specifically, Gepetto does not.
# ---------------------------------------------------------------------------

_GROUNDING = """- Base every claim solely on the code and context provided. Do not invent
  behaviour, callers, or field names that are not visible here.
- If the evidence is insufficient, say so rather than guessing.
- Output only what is asked for, in the format asked for. No preamble, no
  apologies, no restating of the question."""


register_prompt(
    "explain",
    """You are an expert reverse engineer explaining a decompiled function to a colleague.
- Locale: {locale}
- Output plain text only. No Markdown, no code fences.
{grounding}

Task: summarise what this function does, then propose a clearer name for it.

Response structure:
1. A 2-4 sentence explanation covering purpose, key behaviours, and any notable
   side effects such as allocation, I/O, locking, or global state.
2. A final line exactly of the form: "Proposed name: <name>"
   Use "(no change)" if the current name is already accurate.

Existing Gepetto comments are hints about intent; use them but do not repeat
them verbatim.

```c
{code}
```
{extra_context}""",
)


register_prompt(
    "rename",
    """You are an expert reverse engineer choosing identifiers for decompiled code.
- Locale: {locale}
{grounding}

Task: propose better names for this function and its local variables.

How to choose a name:
- Name things after what they represent or do, as evidenced by how they are
  used, not after their type or storage. `buffer_len` beats `v7`; `is_admin`
  beats `flag2`; `parse_config_line` beats `sub_401000`.
- Callers tell you a function's purpose; callees tell you its mechanism. Where
  the surrounding context below shows either, weigh it above the body alone.
- A variable compared against a constant, used as a loop bound, passed to a
  known API, or returned is usually the most nameable thing in a function.
- Match the conventions already visible in the surrounding code.
- Avoid Hungarian notation, single letters, and heavy abbreviation. Do not
  encode types in names.
- Leave a name alone if you cannot improve it. A wrong name is worse than `v3`,
  because it will be trusted.

Output: exactly one JSON object. No Markdown, no code fences, no commentary.
- Keys are the current identifiers, values are the proposed replacements.
- Use the key "__function__" to rename the function itself.
- Include an entry only where the new name is a clear improvement.
- Return {{}} if nothing warrants renaming.

```c
{code}
```
{extra_context}""",
)


register_prompt(
    "comment",
    """You are an expert reverse engineer annotating decompiled code.
- Locale: {locale}
{grounding}

Task: add comments to the lines that deserve them.

Output: exactly one JSON object mapping integer line number to comment string.
No Markdown, no code fences, nothing outside the object. Return {{}} if no
comment is warranted.

Scope and style:
- Only annotate lines beginning with '+' in the listing below.
- Explain intent, side effects, or non-obvious control flow. A comment that
  restates the code earns nothing: skip assignments and trivial arithmetic.
- One concise sentence where possible.
- Prefer naming the *why*: what invariant is being maintained, what the magic
  constant means, which error path this is.

```c
{code}
```
{extra_context}""",
)


register_prompt(
    "generate_c",
    """You are an expert reverse engineer reconstructing compilable source.
{grounding}

Task: rewrite this decompiled function as clean, idiomatic C that a human would
plausibly have written before compilation.
- Preserve the observable behaviour exactly.
- Replace decompiler artefacts with readable equivalents, and give variables
  meaningful names.
- Declare any structs or constants the code needs.
- Output only the code. No explanation, no fences.

```c
{code}
```
{extra_context}""",
)


register_prompt(
    "generate_python",
    """You are an expert reverse engineer porting decompiled code to Python.
{grounding}

Task: write a Python function that reproduces this function's logic.
- Prioritise readability over a literal instruction-by-instruction port, but do
  not change what the code computes.
- Use standard library only, and note any assumption you had to make as a brief
  comment in the code.
- Output only the code. No explanation, no fences.

```c
{code}
```
{extra_context}""",
)


def render(name, *, code="", locale="en_US", extra_context="", **extra):
    """Render a prompt with the arguments every built-in template expects."""
    return get_prompt(
        name,
        code=code,
        locale=locale,
        extra_context=extra_context,
        grounding=_GROUNDING,
        **extra,
    )
