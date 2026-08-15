"""Named prompt templates for Gepetto actions."""

from string import Template


PROMPTS = {
    "explain": """
You are a reverse-engineering assistant. Output plain text only (no Markdown, no code fences).
- Locale: $locale
- Task: Summarize what the C function does and propose a clearer function name if one stands out.
- Observations: Use any existing Gepetto-generated comments as hints but do not repeat them verbatim.
- Response structure:
    1. Brief explanation (2-4 sentences) covering purpose, key behaviours, and notable side effects.
    2. Final line: "Proposed name: <name>" (use "(no change)" if you cannot recommend an improvement).

```C
$code
```
""",
    "rename": """
You are a reverse-engineering assistant refining identifiers.
- Locale: $locale
- Task: Suggest better names for the function and its locals when the improvement is meaningful.
- Output: Return exactly one JSON object (no Markdown, no backticks, no commentary).
    Keys = original identifiers, values = suggested replacements.
    Use the special key "__function__" to propose a new function name.
- Guidance:
    * Only include entries where the proposed name clearly improves clarity.
    * Prefer descriptive, conventional names; avoid Hungarian notation and over-abbreviations.
    * Leverage existing accurate comments (especially Gepetto banners) when inferring intent.
- If nothing needs renaming, respond with {}.

```C
$code
```
""",
    "comment": """
You are a reverse-engineering assistant adding helpful pseudocode comments.
- Locale: $locale
- Output format (strict): exactly one JSON object mapping integer lineNumber -> string comment.
  * No Markdown, no code fences, no explanations outside the JSON object.
  * If no comments are warranted, return {}.
- Scope: Only annotate lines that start with '+' in the listing below.
- Guidance: Explain intent, side-effects, or non-obvious control flow. Skip trivial operations.
- Style: Keep comments concise (one sentence when possible) and use imperative or descriptive voice.

```C
$lines
```
""",
    "generate_c": """Please generate executable C code based on the following decompiled C code and ensure it includes all necessary header files and other information:
$code""",
    "generate_python": """Please generate equivalent Python code based on the following decompiled C code, and provide an example of the function call:
$code""",
}


def get_prompt(name, **values):
    """Render a named action prompt with literal braces left untouched."""
    try:
        template = PROMPTS[name]
    except KeyError as exc:
        raise KeyError(f"Unknown Gepetto prompt: {name}") from exc
    return Template(template).substitute(**values)
