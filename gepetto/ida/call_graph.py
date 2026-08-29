"""Bounded call-graph context for a function and its decompiled neighbours.

This is a domain API, not a model-tool handler.  A user tool can expose it to
the model, while a context provider can call it directly without depending on
tool registration, JSON tool-call objects, or handler globals::

    from gepetto.ida.call_graph import collect_call_graph_context

    context = collect_call_graph_context(ea, direction="callees")

``max_chars_per_function`` is an exact Unicode-code-point limit for every
returned body, including the truncation marker and including the diagnostics
emitted when there is no body to return.  Whether a body is code, a failure or
empty is reported as ``status`` rather than being left for the caller to read
out of the text, because a truncated diagnostic reads exactly like code.

Model-token budgeting is a caller policy because it depends on the selected
model and prompt shape.
"""

from __future__ import annotations

from typing import Any

from gepetto.ida.tools.decompile_function import decompile_function
from gepetto.ida.tools.get_xrefs import get_xrefs_unified
from gepetto.ida.utils.function_helpers import get_func_name, parse_ea, resolve_func
from gepetto.ida.utils.thread_helpers import safe_get_screen_ea


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FUNCTIONS = 8
DEFAULT_MAX_CHARS_PER_FUNCTION = 1200
_TRUNCATION_SUFFIX = "\n// ... truncated ..."


def _function_neighbours(func_ea: int, direction: str) -> list[int]:
    """Return unique function starts reached by call xrefs in ``direction``."""
    xrefs = get_xrefs_unified(
        scope="function",
        subject=hex(func_ea),
        direction="to" if direction == "callers" else "from",
        kind="code",
        only_calls=True,
        collapse_by="from_func" if direction == "callers" else "to_func",
        enrich_names=False,
    )

    endpoint = "from_ea" if direction == "callers" else "to_ea"
    neighbours: list[int] = []
    for xref in xrefs["xrefs"]:
        try:
            function = resolve_func(ea=int(xref[endpoint]))
        except ValueError:
            continue
        if function.start_ea not in neighbours:
            neighbours.append(function.start_ea)
    return neighbours


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    """Cut ``text`` to ``max_chars`` code points, marker included."""
    if len(text) <= max_chars:
        return text, False
    prefix_length = max_chars - len(_TRUNCATION_SUFFIX)
    if prefix_length <= 0:
        return text[:max_chars], True
    return text[:prefix_length] + _TRUNCATION_SUFFIX, True


def _decompiled_body(func_ea: int, max_chars: int) -> tuple[str, bool, str]:
    """The body, bounded, and whether it is a body at all.

    Every path goes through :func:`_truncate`, including the diagnostics: the
    budget is a promise about the returned text, and a failure message is text
    the caller did not ask for and cannot predict the length of.

    Which is why the outcome is reported separately rather than being read
    back out of the string.  ``// decompilation failed: ...`` truncated to a
    few characters is indistinguishable from code, and a caller that cannot
    tell the difference will treat the fragment as evidence.
    """
    try:
        code = str(decompile_function(ea=func_ea))
    except Exception as exc:
        text, truncated = _truncate(f"// decompilation failed: {exc}", max_chars)
        return text, truncated, "failed"
    if not code.strip():
        text, truncated = _truncate("// decompilation produced no output", max_chars)
        return text, truncated, "empty"
    text, truncated = _truncate(code, max_chars)
    return text, truncated, "ok"


def _limit(value: int, name: str, minimum: int) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if limit < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return limit


def _unvisited_neighbour_exists(frontier, seen, root_ea, max_depth) -> bool:
    """Whether anything reachable was left out. Enumerates xrefs, decompiles nothing."""
    for ea, depth, current_direction in frontier:
        if depth >= max_depth:
            continue
        for neighbour in _function_neighbours(ea, current_direction):
            if neighbour != root_ea and neighbour not in seen:
                return True
    return False


def _walk(
    root_ea: int,
    direction: str,
    max_depth: int,
    max_functions: int,
    max_chars_per_function: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Breadth-first neighbourhood of ``root_ea``, excluding the root.

    Traversal state is kept per direction.  A single shared set collapses the
    two: with ``direction="both"``, a function that both calls and is called by
    the root is recorded under whichever direction reached it first, and
    silently dropped from the other, so ``both`` returned less than the union
    of ``callers`` and ``callees``.

    A function reached from both directions is one entry carrying both
    relations rather than two entries, which costs one decompilation instead of
    two and says the more useful thing: that the two functions call each other.
    """
    directions = ["callers", "callees"] if direction == "both" else [direction]
    expanded = {current: {root_ea} for current in directions}
    entries: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    budget_exhausted = False
    frontier = [(root_ea, 0, current) for current in directions]

    # Frontier entries abandoned when the budget filled. They were never
    # enumerated, so whether they held anything is a question to answer rather
    # than assume -- in either direction.
    unexplored: list[tuple[int, int, str]] = []

    while frontier and len(order) < max_functions:
        next_frontier: list[tuple[int, int, str]] = []
        for position, (ea, depth, current_direction) in enumerate(frontier):
            if len(order) >= max_functions:
                unexplored.extend(frontier[position:])
                break
            if depth >= max_depth:
                continue
            relation = "caller" if current_direction == "callers" else "callee"
            for neighbour in _function_neighbours(ea, current_direction):
                if neighbour == root_ea:
                    continue
                existing = entries.get(neighbour)
                if existing is not None:
                    # Free: no new entry, no budget spent, nothing decompiled
                    # twice. Just the fact that this one is reached both ways.
                    if relation not in existing["relations"]:
                        existing["relations"] = sorted(
                            existing["relations"] + [relation])
                    existing["depth"] = min(existing["depth"], depth + 1)
                else:
                    if len(order) >= max_functions:
                        # Reachable evidence we had no room for, which is what
                        # a truncated traversal means.
                        budget_exhausted = True
                        break
                    function = resolve_func(ea=neighbour)
                    code, truncated, status = _decompiled_body(
                        neighbour, max_chars_per_function)
                    entries[neighbour] = {
                        "ea": hex(neighbour),
                        "name": get_func_name(function) or f"sub_{neighbour:X}",
                        "relations": [relation],
                        "depth": depth + 1,
                        "code": code,
                        "truncated": truncated,
                        "status": status,
                    }
                    order.append(neighbour)
                if neighbour not in expanded[current_direction]:
                    expanded[current_direction].add(neighbour)
                    next_frontier.append((neighbour, depth + 1, current_direction))
        frontier = next_frontier

    if not budget_exhausted and len(order) >= max_functions:
        # Nothing was refused on the way, so the budget filled exactly. Whether
        # the nodes it stopped short of held anything is still a question, and
        # answering it is cheaper than being wrong about it.
        budget_exhausted = _unvisited_neighbour_exists(
            unexplored + frontier, set(entries), root_ea, max_depth)

    return [entries[ea] for ea in order], budget_exhausted


def collect_call_graph_context(
    ea: int | str | None = None,
    *,
    direction: str = "both",
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_chars_per_function: int = DEFAULT_MAX_CHARS_PER_FUNCTION,
) -> dict[str, Any]:
    """Return a bounded breadth-first call-graph slice around a function.

    The returned root and each neighbour include a decompiled body.  This is a
    library API: callers own policy such as configuration and prompt budgets.
    """
    if direction not in {"callers", "callees", "both"}:
        raise ValueError(f"direction must be callers, callees or both (got {direction!r})")

    max_depth = _limit(max_depth, "max_depth", 0)
    max_functions = _limit(max_functions, "max_functions", 0)
    max_chars_per_function = _limit(max_chars_per_function, "max_chars_per_function", 1)

    root_ea = parse_ea(ea) if ea is not None else safe_get_screen_ea()
    root_function = resolve_func(ea=root_ea)
    root_ea = root_function.start_ea
    root_code, root_truncated, root_status = _decompiled_body(
        root_ea, max_chars_per_function)
    neighbours, budget_exhausted = _walk(
        root_ea,
        direction,
        max_depth,
        max_functions,
        max_chars_per_function,
    )

    return {
        "root": {
            "ea": hex(root_ea),
            "name": get_func_name(root_function) or f"sub_{root_ea:X}",
            "code": root_code,
            "truncated": root_truncated,
            "status": root_status,
        },
        "neighbours": neighbours,
        "limits": {
            "direction": direction,
            "max_depth": max_depth,
            "max_functions": max_functions,
            "returned": len(neighbours),
            # Reachable evidence was left out -- not merely that the budget
            # happened to fill exactly.
            "budget_exhausted": budget_exhausted,
        },
    }


__all__ = ["collect_call_graph_context"]
