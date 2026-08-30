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

import sys

from dataclasses import dataclass, field, replace
from typing import Any, NamedTuple, TypedDict

# A version check rather than try/except ImportError: both say the same thing
# to the interpreter, but only this one says it to a type checker, which reads
# sys.version_info natively and otherwise collapses StrEnum to str -- taking
# Direction, Relation and BodyStatus down with it.
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:  # 3.10, which this project still supports
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """What 3.11 added, for the version below it.

        A bare ``(str, Enum)`` is not the same thing: it serialises correctly
        but ``str()`` and f-strings render it as ``ClassName.MEMBER``, so the
        first log line or prompt that interpolates one prints the wrong thing.
        These two assignments are what StrEnum does about that.
        """

        __str__ = str.__str__
        __format__ = str.__format__  # type: ignore[assignment]

from gepetto.ida.tools.decompile_function import decompile_function
from gepetto.ida.tools.get_xrefs import get_xrefs_unified
from gepetto.ida.utils.function_helpers import get_func_name, parse_ea, resolve_func
from gepetto.ida.utils.thread_helpers import safe_get_screen_ea


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FUNCTIONS = 8
DEFAULT_MAX_CHARS_PER_FUNCTION = 1200
_TRUNCATION_SUFFIX = "\n// ... truncated ..."
_TRUNCATION_PREFIX = "// ... truncated ...\n"


class BodyStatus(StrEnum):
    """Whether a returned body is code, and if it is not, why not.

    A string enum rather than a plain one: the tool payload goes through
    json.dumps, which refuses a bare Enum -- and would refuse it in the tool
    path only, long after the collector's own tests had passed.
    """

    OK = "ok"
    FAILED = "failed"
    EMPTY = "empty"


class XrefQuery(NamedTuple):
    """How to ask the xref API for the edges going one way.

    Three values that have to agree with each other -- ``to`` pairs with
    ``from_func`` and ``from_ea``, never with the others -- so they are one
    thing rather than three conditionals in a row that each have to be got
    right separately.
    """

    direction: str
    collapse_by: str
    endpoint: str


class Direction(StrEnum):
    """Which way to walk. Plural, because it names a set of edges."""

    CALLERS = "callers"
    CALLEES = "callees"
    BOTH = "both"

    @property
    def xrefs(self) -> XrefQuery:
        """How to ask for this direction's edges.

        BOTH walks two ways, so it has no single query and says so rather
        than quietly answering for one of them.
        """
        try:
            return _XREF_QUERY[self]
        except KeyError:
            raise ValueError(f"{self} walks two ways, not one") from None

    @classmethod
    def parse(cls, value: str) -> Direction:
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
    def for_direction(cls, direction: Direction) -> Relation:
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


_XREF_QUERY = {
    Direction.CALLERS: XrefQuery("to", "from_func", "from_ea"),
    Direction.CALLEES: XrefQuery("from", "to_func", "to_ea"),
}

_RELATION_FOR_DIRECTION = {
    Direction.CALLERS: Relation.CALLER,
    Direction.CALLEES: Relation.CALLEE,
}


class NeighbourPayload(TypedDict):
    """One neighbour as it leaves this module.

    Written down because the consumer reads it by key, and a key renamed on
    one side of that is invisible: when ``relation`` became ``relations`` the
    prompt silently labelled every neighbour "neighbour" and every test still
    passed.  Nothing type-checks this project, so the guarantee comes from
    ``test_the_payload_matches_the_shape_it_promises`` rather than from mypy.
    """

    ea: str
    name: str
    relations: list[Relation]
    depth: int
    code: str
    truncated: bool
    status: BodyStatus


class RootPayload(TypedDict):
    """The function asked about. It has no relation to itself, and no depth."""

    ea: str
    name: str
    code: str
    truncated: bool
    status: BodyStatus


class LimitsPayload(TypedDict):
    """What was asked for, and whether it was enough."""

    direction: Direction
    max_depth: int
    max_functions: int
    returned: int
    budget_exhausted: bool


class CallGraphContext(TypedDict):
    """The whole slice."""

    root: RootPayload
    neighbours: list[NeighbourPayload]
    limits: LimitsPayload


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


@dataclass(frozen=True)
class _Window:
    """A run of lines, and what it costs to show them.

    ``len(window)`` is the rendered size and ``str(window)`` is the rendering.
    Two computations of one fact, so the elision markers are decided once here
    rather than in each: a marker either side disagreed about would put the
    rendered text over a budget that had been measured as fitting.

    ``len`` is the one called repeatedly, so it counts characters instead of
    building the string to measure it.
    """

    lines: list[str]
    first: int
    last: int

    @property
    def elisions(self) -> tuple[str, str]:
        """What marks the lines dropped before and after this window."""
        return (
            _TRUNCATION_PREFIX if self.first else "",
            _TRUNCATION_SUFFIX if self.last + 1 < len(self.lines) else "",
        )

    def __len__(self) -> int:
        head, tail = self.elisions
        kept = self.lines[self.first:self.last + 1]
        # One newline between lines, which is what "\n".join adds.
        return sum(map(len, kept)) + (self.last - self.first) + len(head) + len(tail)

    def __str__(self) -> str:
        head, tail = self.elisions
        return head + "\n".join(self.lines[self.first:self.last + 1]) + tail


def _window(text: str, max_chars: int, anchor: str | None) -> Truncated:
    """Cut ``text`` to ``max_chars``, keeping the part that mentions ``anchor``.

    Head truncation is the wrong shape for a caller.  What a caller is evidence
    of is the call itself -- which arguments reach the function being explained
    -- and that is almost never in the prologue.  Cutting the 382 caller bodies
    of the test binary that name their callee to the same 600 characters, from
    identical decompiled text, the head keeps the call site in 54% of them and
    this keeps it in all of them, at 404 characters against 410.

    Budget is not the fix, which is what makes it a shape problem rather than a
    size one.  Over a separate sample -- 171 bodies, counted over every caller
    rather than only those naming their callee, so its rates do not compare
    with the figures above -- raising the limit from 600 to 5000 moved
    call-site visibility from 19% to 46%, at 3.5x the prompt cost.

    So when the caller names its callee, the window is centred on that line and
    grown outwards until the budget is spent.  ``anchor`` is ``None`` for a
    callee, which wants its head anyway, and an anchor that does not appear --
    an indirect call, a tail jump, a thunk -- falls back to the head.

    The budget stays an exact promise: both elision markers are counted.
    """
    if len(text) <= max_chars:
        return Truncated(text, False)

    lines = text.splitlines()
    call_site = next(
        (n for n, line in enumerate(lines) if anchor and anchor in line), None)
    if call_site is None:
        return _truncate(text, max_chars)

    window = _Window(lines, call_site, call_site)
    if len(window) > max_chars:
        # The call site alone overruns the budget. Its head is still the most
        # relevant text available, which is not true of the function's head.
        return Truncated(_truncate(lines[call_site], max_chars).text, True)

    # One line at a time, each side measured against the window the other side
    # just grew -- not against the window both started from. Testing the two
    # independently and keeping both is the tempting shape, and it overruns the
    # budget whenever the two fit separately but not together.
    while True:
        bounds = window.first, window.last
        if window.first:
            wider = replace(window, first=window.first - 1)
            if len(wider) <= max_chars:
                window = wider
        if window.last + 1 < len(lines):
            wider = replace(window, last=window.last + 1)
            if len(wider) <= max_chars:
                window = wider
        if (window.first, window.last) == bounds:
            break
    return Truncated(str(window), True)


def _decompiled_body(func_ea: int, max_chars: int,
                     anchor: str | None = None) -> Body:
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
    cut = _window(code, max_chars, anchor)
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

    @property
    def relation(self) -> str:
        """How the root reaches this function, as one phrase.

        A neighbour reached from both directions carries both relations, so
        "caller, callee" is a fact about the pair worth saying.
        """
        return ", ".join(self.relations) if self.relations else "neighbour"

    @property
    def label(self) -> str:
        """How this neighbour introduces itself as evidence."""
        return f"[{self.relation}, depth {self.depth}] {self.name} ({hex(self.ea)})"

    def as_payload(self) -> NeighbourPayload:
        return {
            "ea": hex(self.ea),
            "name": self.name,
            "relations": list(self.relations),
            "depth": self.depth,
            "code": self.body.text,
            "truncated": self.body.truncated,
            "status": self.body.status,
        }


@dataclass
class Root:
    """The function asked about. It has no relation to itself, and no depth."""

    ea: int
    name: str
    body: Body

    def as_payload(self) -> RootPayload:
        return {
            "ea": hex(self.ea),
            "name": self.name,
            "code": self.body.text,
            "truncated": self.body.truncated,
            "status": self.body.status,
        }


@dataclass
class Limits:
    """What was asked for, and whether it was enough."""

    direction: Direction
    max_depth: int
    max_functions: int
    returned: int
    budget_exhausted: bool

    def as_payload(self) -> LimitsPayload:
        return {
            "direction": self.direction,
            "max_depth": self.max_depth,
            "max_functions": self.max_functions,
            "returned": self.returned,
            "budget_exhausted": self.budget_exhausted,
        }


@dataclass
class CallGraphSlice:
    """A bounded neighbourhood of one function, as objects.

    :func:`collect_call_graph_context` is this flattened for a JSON tool call.
    A caller inside the process should ask for the slice instead: reading the
    payload by key is how ``relation`` became ``relations`` unnoticed, and a
    neighbour knows how to introduce itself without being taken apart first.
    """

    root: Root
    neighbours: list[Neighbour]
    limits: Limits

    def as_payload(self) -> CallGraphContext:
        return {
            "root": self.root.as_payload(),
            "neighbours": [n.as_payload() for n in self.neighbours],
            "limits": self.limits.as_payload(),
        }


def _function_neighbours(func_ea: int, direction: Direction) -> list[int]:
    """Return unique function starts reached by call xrefs in ``direction``."""
    query = Direction.parse(direction).xrefs
    xrefs = get_xrefs_unified(
        scope="function",
        subject=hex(func_ea),
        direction=query.direction,
        kind="code",
        only_calls=True,
        collapse_by=query.collapse_by,
        enrich_names=False,
    )

    neighbours: list[int] = []
    for xref in xrefs["xrefs"]:
        try:
            function = resolve_func(ea=int(xref[query.endpoint]))
        except ValueError:
            continue
        if function.start_ea not in neighbours:
            neighbours.append(function.start_ea)
    return neighbours


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
    root_name: str,
    direction: Direction,
    max_depth: int,
    max_functions: int,
    max_chars_per_function: int,
) -> tuple[list[Neighbour], bool]:
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
    # What each expanded function is called, so a caller's body can be cut
    # around the line that names the function it was reached from.
    names = {root_ea: root_name}
    order: list[int] = []
    budget_exhausted = False
    frontier = [(root_ea, 0, current) for current in directions]

    # Frontier entries abandoned when the budget filled. They were never
    # enumerated, so whether they held anything is a question to answer rather
    # than assume -- in either direction.
    unexplored: list[tuple[int, int, Direction]] = []

    while frontier and len(order) < max_functions:
        next_frontier: list[tuple[int, int, Direction]] = []
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
                    name = get_func_name(function) or f"sub_{neighbour:X}"
                    names[neighbour] = name
                    entries[neighbour] = Neighbour(
                        ea=neighbour,
                        name=name,
                        depth=depth + 1,
                        body=_decompiled_body(
                            neighbour,
                            max_chars_per_function,
                            # Only a caller has a call site to keep.
                            names.get(ea) if relation is Relation.CALLER else None,
                        ),
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

    return [entries[ea] for ea in order], budget_exhausted


def collect_call_graph_slice(
    ea: int | str | None = None,
    *,
    direction: Direction | str = Direction.BOTH,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_chars_per_function: int = DEFAULT_MAX_CHARS_PER_FUNCTION,
) -> CallGraphSlice:
    """Return a bounded breadth-first call-graph slice around a function.

    The root and each neighbour carry a decompiled body.  This is a library
    API: callers own policy such as configuration and prompt budgets.

    In-process callers want this rather than
    :func:`collect_call_graph_context`, which flattens it for a JSON tool
    call and loses the behaviour with the keys.
    """
    wanted = Direction.parse(direction)

    max_depth = _limit(max_depth, "max_depth", 0)
    max_functions = _limit(max_functions, "max_functions", 0)
    max_chars_per_function = _limit(max_chars_per_function, "max_chars_per_function", 1)

    root_ea = parse_ea(ea) if ea is not None else safe_get_screen_ea()
    root_function = resolve_func(ea=root_ea)
    root_ea = root_function.start_ea
    root_name = get_func_name(root_function) or f"sub_{root_ea:X}"
    # Before the walk, so the root is decompiled first: an inlined call in the
    # constructor below would quietly reorder the decompiler's work.
    root_body = _decompiled_body(root_ea, max_chars_per_function)
    neighbours, budget_exhausted = _walk(
        root_ea,
        root_name,
        wanted,
        max_depth,
        max_functions,
        max_chars_per_function,
    )

    return CallGraphSlice(
        root=Root(ea=root_ea, name=root_name, body=root_body),
        neighbours=neighbours,
        limits=Limits(
            direction=wanted,
            max_depth=max_depth,
            max_functions=max_functions,
            returned=len(neighbours),
            # Reachable evidence was left out -- not merely that the budget
            # happened to fill exactly.
            budget_exhausted=budget_exhausted,
        ),
    )


def collect_call_graph_context(
    ea: int | str | None = None,
    *,
    direction: Direction | str = Direction.BOTH,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_chars_per_function: int = DEFAULT_MAX_CHARS_PER_FUNCTION,
) -> CallGraphContext:
    """The same slice, flattened for a JSON tool call."""
    return collect_call_graph_slice(
        ea,
        direction=direction,
        max_depth=max_depth,
        max_functions=max_functions,
        max_chars_per_function=max_chars_per_function,
    ).as_payload()


__all__ = ["BodyStatus", "CallGraphContext", "CallGraphSlice",
           "NeighbourPayload", "collect_call_graph_context",
           "collect_call_graph_slice"]
