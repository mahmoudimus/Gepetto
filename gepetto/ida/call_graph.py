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

from dataclasses import dataclass, field
from typing import Any, NamedTuple

try:  # 3.11+
    from enum import StrEnum
except ImportError:  # 3.10, which this project still supports
    from enum import Enum

    class StrEnum(str, Enum):
        """What 3.11 added, for the version below it.

        A bare ``(str, Enum)`` is not the same thing: it serialises correctly
        but ``str()`` and f-strings render it as ``ClassName.MEMBER``, so the
        first log line or prompt that interpolates one prints the wrong thing.
        These two assignments are what StrEnum does about that.
        """

        __str__ = str.__str__
        __format__ = str.__format__

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


class BodyStatus(StrEnum):
    """Whether a returned body is code, and if it is not, why not.

    A string enum rather than a plain one: the tool payload goes through
    json.dumps, which refuses a bare Enum -- and would refuse it in the tool
    path only, long after the collector's own tests had passed.
    """

    OK = "ok"
    FAILED = "failed"
    EMPTY = "empty"


class Direction(StrEnum):
    """Which way to walk. Plural, because it names a set of edges."""

    CALLERS = "callers"
    CALLEES = "callees"
    BOTH = "both"

    @classmethod
    def parse(cls, value: str) -> "Direction":
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"direction must be callers, callees or both (got {value!r})"
            ) from None


class Relation(StrEnum):
    """How one neighbour is attached to the root. Singular."""

    CALLER = "caller"
    CALLEE = "callee"

    @classmethod
    def for_direction(cls, direction: "Direction") -> "Relation":
        """The relation a neighbour has when reached walking this way.

        A mapping rather than a conditional, because the conditional had an
        else: anything that was not "callers" came back as CALLEE, so a typo,
        an empty string and None all produced a confident wrong answer. BOTH
        is the case that makes it a real question -- it names two relations,
        so asking it for one is a mistake worth hearing about.
        """
        try:
            return _RELATION_FOR_DIRECTION[Direction.parse(direction)]
        except KeyError:
            raise ValueError(
                f"{direction!r} names two relations, not one") from None


_RELATION_FOR_DIRECTION = {
    Direction.CALLERS: Relation.CALLER,
    Direction.CALLEES: Relation.CALLEE,
}


class Truncated(NamedTuple):
    """Text, and whether it had to be cut to fit."""

    text: str
    truncated: bool


class Body(NamedTuple):
    """A function body as it will be reported.

    Named rather than a bare tuple because it grew: adding ``status`` to a
    three-value tuple silently broke every caller that unpacked two, and the
    next field would do it again.
    """

    text: str
    truncated: bool
    status: BodyStatus


def _truncate(text: str, max_chars: int) -> Truncated:
    """Cut ``text`` to ``max_chars`` code points, marker included."""
    if len(text) <= max_chars:
        return Truncated(text, False)
    prefix_length = max_chars - len(_TRUNCATION_SUFFIX)
    if prefix_length <= 0:
        return Truncated(text[:max_chars], True)
    return Truncated(text[:prefix_length] + _TRUNCATION_SUFFIX, True)


def _decompiled_body(func_ea: int, max_chars: int) -> Body:
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
        cut = _truncate(f"// decompilation failed: {exc}", max_chars)
        return Body(cut.text, cut.truncated, BodyStatus.FAILED)
    if not code.strip():
        cut = _truncate("// decompilation produced no output", max_chars)
        return Body(cut.text, cut.truncated, BodyStatus.EMPTY)
    cut = _truncate(code, max_chars)
    return Body(cut.text, cut.truncated, BodyStatus.OK)


def _limit(value: int, name: str, minimum: int) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if limit < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return limit


@dataclass
class Neighbour:
    """One function next to the root, and how it is next to it.

    The merge below is why this is a class rather than a dict. Reaching the
    same function from both directions has to keep the relations unique and
    ordered and take the nearer depth, and those three rules were previously
    three lines at the one call site that happened to need them -- which is
    where invariants go to be forgotten.
    """

    ea: int
    name: str
    depth: int
    body: Body
    relations: list[Relation] = field(default_factory=list)

    def also_reached_as(self, relation: Relation, depth: int) -> None:
        """Record that the root reaches this function this way too."""
        if relation not in self.relations:
            self.relations = sorted(self.relations + [relation])
        self.depth = min(self.depth, depth)

    def as_payload(self) -> dict[str, Any]:
        return {
            "ea": hex(self.ea),
            "name": self.name,
            "relations": list(self.relations),
            "depth": self.depth,
            "code": self.body.text,
            "truncated": self.body.truncated,
            "status": self.body.status,
        }


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
    directions = ([Direction.CALLERS, Direction.CALLEES]
                  if direction is Direction.BOTH else [direction])
    expanded = {current: {root_ea} for current in directions}
    entries: dict[int, Neighbour] = {}
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
            relation = Relation.for_direction(current_direction)
            for neighbour in _function_neighbours(ea, current_direction):
                if neighbour == root_ea:
                    continue
                existing = entries.get(neighbour)
                if existing is not None:
                    # Free: no new entry, no budget spent, nothing decompiled
                    # twice. Just the fact that this one is reached both ways.
                    existing.also_reached_as(relation, depth + 1)
                else:
                    if len(order) >= max_functions:
                        # Reachable evidence we had no room for, which is what
                        # a truncated traversal means.
                        budget_exhausted = True
                        break
                    function = resolve_func(ea=neighbour)
                    entries[neighbour] = Neighbour(
                        ea=neighbour,
                        name=get_func_name(function) or f"sub_{neighbour:X}",
                        depth=depth + 1,
                        body=_decompiled_body(neighbour, max_chars_per_function),
                        relations=[relation],
                    )
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

    return [entries[ea].as_payload() for ea in order], budget_exhausted


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
    direction = Direction.parse(direction)

    max_depth = _limit(max_depth, "max_depth", 0)
    max_functions = _limit(max_functions, "max_functions", 0)
    max_chars_per_function = _limit(max_chars_per_function, "max_chars_per_function", 1)

    root_ea = parse_ea(ea) if ea is not None else safe_get_screen_ea()
    root_function = resolve_func(ea=root_ea)
    root_ea = root_function.start_ea
    root = _decompiled_body(root_ea, max_chars_per_function)
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
            "code": root.text,
            "truncated": root.truncated,
            "status": root.status,
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


__all__ = ["BodyStatus", "collect_call_graph_context"]
