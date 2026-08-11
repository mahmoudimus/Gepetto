"""Prompt templates for the hotkey actions.

The prompts used to be f-strings buried in the handlers, so improving one meant
editing plugin source that an upgrade overwrites, and comparing two wordings
meant a code change. They live here as named templates, and a user can replace
any of them from $IDAUSR/cfg/gepetto/prompts without touching the plugin:

    from gepetto.ida.prompts import register_prompt
    register_prompt("rename", '''...my wording, $code ...''')

Rendered with string.Template, so placeholders are $name or ${name} and braces
are literal. That matters here because these prompts are mostly JSON examples:
under str.format every brace in them had to be doubled, which made the example
the model is meant to copy differ from what it should emit.

Substitution is "safe": an unknown $placeholder is left as written rather than
raising, and substituted values are not rescanned, so decompiled code
containing braces or a $LN10 label passes through untouched. A custom template
may use as few placeholders as it likes.
"""

import importlib.util
import pathlib
import traceback
from string import Template

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

    safe_substitute leaves an unrecognised $placeholder in place instead of
    raising, so a typo in a user-supplied template costs that one substitution
    rather than the action the user asked for.
    """
    template = PROMPTS.get(name)
    if template is None:
        raise KeyError(f"No prompt registered under {name!r}")
    try:
        return Template(template).safe_substitute(kwargs)
    except Exception as e:
        print(f"Gepetto: prompt '{name}' could not be rendered ({e!r}); sending it unrendered.")
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
- Locale: $locale
- Output plain text only. No Markdown, no code fences.
$grounding

Task: summarise what this function does, then propose a clearer name for it.

Response structure:
1. A 2-4 sentence explanation covering purpose, key behaviours, and any notable
   side effects such as allocation, I/O, locking, or global state.
2. A final line exactly of the form: "Proposed name: <name>"
   Use "(no change)" if the current name is already accurate.

Existing Gepetto comments are hints about intent; use them but do not repeat
them verbatim.

```c
$code
```
$extra_context""",
)


register_prompt(
    "rename",
    """You are an expert reverse engineer choosing identifiers for decompiled code.
- Locale: $locale
$grounding

Task: propose better names for this function, its local variables, and any
global symbols it touches that still carry compiler-generated names -- things
like `qword_140C1A0`, `off_1401234`, `unk_140998`, `byte_14055`. A global is
worth naming when this function's use of it reveals what it holds; leave it
alone when the only evidence is that it was read.

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
- Keys are the current identifiers. Each value is an object:
  {"name": "<proposed name>", "why": "<the evidence for it>"}
- Use the key "__function__" to rename the function itself.
- Globals use their current name as the key, exactly as it appears.
- Include an entry only where the new name is a clear improvement.
- Return {} if nothing warrants renaming.

Renaming a global changes it everywhere in the database, not just here, so
hold those to a higher bar than a local: name one only when this function
shows what it is for.

The "why" is not a restatement of the name. Cite what in the code justifies
it: which call it is passed to, what it is compared against, which field it
indexes, which caller supplies it. One clause is enough. A name you cannot
justify from the code in front of you is a name you should not propose.

Example:
{"__function__": {"name": "parse_config_line",
                  "why": "splits on '=' and stores into the table its caller
                          later reads with lookup_setting"},
 "v7": {"name": "line_len", "why": "bound of the copy loop, from strlen(a1)"}}

```c
$code
```
$extra_context""",
)


register_prompt(
    "comment",
    """You are an expert reverse engineer annotating decompiled code.
- Locale: $locale
$grounding

Task: add comments to the lines that deserve them.

Output: exactly one JSON object mapping integer line number to comment string.
No Markdown, no code fences, nothing outside the object. Return {} if no
comment is warranted.

Scope and style:
- Only annotate lines beginning with '+' in the listing below.
- Explain intent, side effects, or non-obvious control flow. A comment that
  restates the code earns nothing: skip assignments and trivial arithmetic.
- One concise sentence where possible.
- Prefer naming the *why*: what invariant is being maintained, what the magic
  constant means, which error path this is.

```c
$code
```
$extra_context""",
)


register_prompt(
    "generate_c",
    """You are an expert reverse engineer reconstructing compilable source.
$grounding

Task: rewrite this decompiled function as clean, idiomatic C that a human would
plausibly have written before compilation.
- Preserve the observable behaviour exactly.
- Replace decompiler artefacts with readable equivalents, and give variables
  meaningful names.
- Declare any structs or constants the code needs.
- Output only the code. No explanation, no fences.

```c
$code
```
$extra_context""",
)


register_prompt(
    "generate_python",
    """You are an expert reverse engineer porting decompiled code to Python.
$grounding

Task: write a Python function that reproduces this function's logic.
- Prioritise readability over a literal instruction-by-instruction port, but do
  not change what the code computes.
- Use standard library only, and note any assumption you had to make as a brief
  comment in the code.
- Output only the code. No explanation, no fences.

```c
$code
```
$extra_context""",
)


register_prompt(
    "generate_struct",
    """You are an expert reverse engineer naming a structure recovered from code.
- Locale: $locale
$grounding

The layout below was derived from the code, not guessed: every offset, width
and read/write count was observed. Do not change them, do not add fields that
were never accessed, and do not remove the gaps -- a gap means those bytes were
never touched by the code that was scanned, so their contents are unknown.

Task: name the structure and its fields, and say what each field is for.

- Base each name on how the field is used: what it is compared against, what it
  is passed to, which function reads it. "reads/writes" tells you a lot -- a
  field only ever written is likely an output or a cached value; one read in
  several functions is likely configuration or state.
- Where a field's type is ambiguous the alternatives observed are listed. Say
  which you think it is and why.
- Leave a field named field_<offset> if the evidence does not support better.
  An invented name is worse than no name.

Output: exactly one JSON object. No Markdown, no code fences, no commentary.
{"struct_name": "<name>",
 "fields": {"<offset_hex>": {"name": "<field name>",
                             "why": "<the evidence>"}},
 "purpose": "<one sentence on what the structure represents>"}

Offsets are the keys, exactly as given below.

Observed layout:
$layout

Code that uses it:
```c
$code
```
$extra_context""",
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
