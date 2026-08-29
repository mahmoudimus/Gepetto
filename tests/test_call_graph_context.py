from types import SimpleNamespace

from gepetto.ida import call_graph


def test_collect_call_graph_context_uses_breadth_first_order_within_the_budget(monkeypatch):
    graph = {
        0x100: [0x200, 0x300],
        0x200: [0x400],
        0x300: [0x500],
    }

    monkeypatch.setattr(
        call_graph,
        "resolve_func",
        lambda ea: SimpleNamespace(start_ea=ea),
    )
    monkeypatch.setattr(
        call_graph,
        "get_func_name",
        lambda function: f"function_{function.start_ea:X}",
    )
    monkeypatch.setattr(
        call_graph,
        "_function_neighbours",
        lambda ea, _direction: graph.get(ea, []),
    )
    monkeypatch.setattr(
        call_graph,
        "_decompiled_body",
        lambda ea, _max_chars, _anchor=None: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK),
    )

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=2,
        max_functions=3,
        max_chars_per_function=80,
    )

    assert result["root"] == {
        "ea": "0x100",
        "name": "function_100",
        "code": "body_100",
        "truncated": False,
        "status": "ok",
    }
    assert result["neighbours"] == [
        {
            "ea": "0x200",
            "name": "function_200",
            "relations": ["callee"],
            "status": "ok",
            "depth": 1,
            "code": "body_200",
            "truncated": False,
        },
        {
            "ea": "0x300",
            "name": "function_300",
            "relations": ["callee"],
            "status": "ok",
            "depth": 1,
            "code": "body_300",
            "truncated": False,
        },
        {
            "ea": "0x400",
            "name": "function_400",
            "relations": ["callee"],
            "status": "ok",
            "depth": 2,
            "code": "body_400",
            "truncated": False,
        },
    ]
    assert result["limits"] == {
        "direction": "callees",
        "max_depth": 2,
        "max_functions": 3,
        "returned": 3,
        "budget_exhausted": True,
    }


def test_collect_call_graph_context_skips_call_targets_outside_a_function(monkeypatch):
    def resolve_function(ea):
        if ea == 0xDEAD:
            raise ValueError("EA 0xDEAD is not inside a function")
        return SimpleNamespace(start_ea=ea)

    monkeypatch.setattr(call_graph, "resolve_func", resolve_function)
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(
        call_graph,
        "get_xrefs_unified",
        lambda **kwargs: {
            "xrefs": [
                {"to_ea": 0xDEAD},
                {"to_ea": 0x200},
            ] if kwargs["subject"] == "0x100" else [],
        },
    )
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _max_chars, _anchor=None: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=1,
        max_functions=2,
    )

    assert [neighbour["ea"] for neighbour in result["neighbours"]] == ["0x200"]


def test_decompiled_body_honors_an_exact_unicode_code_point_budget(monkeypatch):
    monkeypatch.setattr(
        call_graph,
        "decompile_function",
        lambda **_kwargs: "\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6\u03b7\u03b8\u03b9\u03ba\u03bb\u03bc\u03bd\u03be\u03bf\u03c0\u03c1\u03c3\u03c4\u03c5\u03c6\u03c7\u03c8\u03c9\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6",
    )

    code, truncated, status = call_graph._decompiled_body(0x100, 25)

    assert code == "\u03b1\u03b2\u03b3\u03b4\n// ... truncated ..."
    assert len(code) == 25
    assert code.encode("utf-8").decode("utf-8") == code
    assert truncated is True


def test_collect_call_graph_context_honors_an_explicit_body_budget(monkeypatch):
    seen_budgets = []

    monkeypatch.setattr(call_graph, "resolve_func", lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours", lambda *_args: [])
    monkeypatch.setattr(
        call_graph,
        "_decompiled_body",
        lambda _ea, budget, _anchor=None: call_graph.Body(seen_budgets.append(budget) or f"body_budget_{budget}", False, call_graph.BodyStatus.OK),
    )

    result = call_graph.collect_call_graph_context(0x100, max_chars_per_function=7)

    assert result["root"]["code"] == "body_budget_7"
    assert seen_budgets == [7]


def test_collect_call_graph_context_allows_a_zero_depth_budget(monkeypatch):
    monkeypatch.setattr(call_graph, "resolve_func", lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours", lambda *_args: [0x200])
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _budget, _anchor=None: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=0,
        max_functions=1,
    )

    assert result["neighbours"] == []
    assert result["limits"]["max_depth"] == 0


def _fake_graph(monkeypatch, graph, bodies=None):
    """A call graph with no IDA behind it.

    ``graph`` maps ``(ea, direction)`` to neighbours, so a test can make two
    functions call each other and have the traversal see it from both sides.
    """
    monkeypatch.setattr(call_graph, "resolve_func",
                        lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name",
                        lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours",
                        lambda ea, direction: graph.get((ea, direction), []))
    if bodies is None:
        monkeypatch.setattr(call_graph, "_decompiled_body",
                            lambda ea, _budget, _anchor=None: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))


# --- every returned body is bounded, diagnostics included --------------------

def test_a_decompilation_failure_is_bounded_like_any_other_body(monkeypatch):
    """A failure message is text the caller did not ask for and cannot size."""
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("boom " * 200)))

    code, truncated, status = call_graph._decompiled_body(0x100, 40)

    assert len(code) == 40
    assert truncated is True
    assert status == "failed"


def test_an_empty_decompilation_is_bounded_too(monkeypatch):
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "   \n  ")

    code, truncated, status = call_graph._decompiled_body(0x100, 12)

    assert len(code) == 12
    assert truncated is True
    assert status == "empty"


def test_the_smallest_budget_still_holds_on_every_path(monkeypatch):
    """max_chars_per_function=1 is the case that made the bug obvious."""
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "int f(void) { return 1; }")
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1

    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "")
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1

    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("nope")))
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1


def test_status_survives_a_bound_that_destroys_the_message(monkeypatch):
    """Truncated to a character, `/` is indistinguishable from code."""
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("nope")))

    _code, _truncated, status = call_graph._decompiled_body(0x100, 1)

    assert status == "failed"


def test_a_body_that_fits_is_not_marked_truncated(monkeypatch):
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "int f;")

    code, truncated, status = call_graph._decompiled_body(0x100, 80)

    assert (code, truncated, status) == ("int f;", False, "ok")


# --- direction="both" must not lose a relation -------------------------------

def test_mutual_recursion_is_reported_from_both_sides(monkeypatch):
    """A single visited set records B under whichever direction reached it
    first and drops the other, so `both` returned less than callers plus
    callees."""
    _fake_graph(monkeypatch, {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x200],
        (0x200, "callers"): [0x100],
        (0x200, "callees"): [0x100],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert len(result["neighbours"]) == 1, "one function, not two entries"
    assert result["neighbours"][0]["relations"] == ["callee", "caller"]


def test_both_returns_the_union_of_the_single_directions(monkeypatch):
    graph = {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x300],
    }
    _fake_graph(monkeypatch, graph)

    def names(direction):
        found = call_graph.collect_call_graph_context(
            0x100, direction=direction, max_depth=1, max_functions=8)
        return {n["ea"] for n in found["neighbours"]}

    assert names("both") == names("callers") | names("callees")


def test_a_one_sided_neighbour_keeps_its_single_relation(monkeypatch):
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert result["neighbours"][0]["relations"] == ["callee"]


def test_a_neighbour_reached_twice_is_decompiled_once(monkeypatch):
    """Aggregating is not only tidier output; it halves the work."""
    decompiled = []
    _fake_graph(monkeypatch, {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x200],
    }, bodies=True)
    monkeypatch.setattr(
        call_graph, "_decompiled_body",
        lambda ea, _budget, _anchor=None: call_graph.Body(decompiled.append(ea) or f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert decompiled.count(0x200) == 1, "reached as caller and as callee"
    assert decompiled == [0x100, 0x200], "the root, then the neighbour, once"


def test_the_nearer_depth_wins_when_a_neighbour_is_reached_twice(monkeypatch):
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200],
        (0x200, "callees"): [0x300],
        (0x100, "callers"): [0x300],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=2, max_functions=8)

    reached = {n["ea"]: n for n in result["neighbours"]}
    assert reached["0x300"]["depth"] == 1, "a caller at depth 1 beats a callee at 2"
    assert reached["0x300"]["relations"] == ["callee", "caller"]


# --- budget_exhausted means truncated, not merely full -----------------------

def test_a_budget_that_fills_exactly_is_not_a_truncation(monkeypatch):
    """The old flag was `returned == max_functions`, true even when the graph
    had nothing else to give."""
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200, 0x300]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is False


def test_evidence_left_out_is_reported_as_truncation(monkeypatch):
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200, 0x300, 0x400]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is True


def test_a_neighbour_cut_off_a_level_down_still_counts(monkeypatch):
    """The budget can fill exactly as a depth finishes, leaving whole nodes
    unexplored. Nothing was refused on the way, so it takes a look to tell."""
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200, 0x300],
        (0x300, "callees"): [0x400],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is True


def test_an_already_seen_neighbour_is_not_counted_as_lost(monkeypatch):
    """Re-reaching a function already returned is not evidence left out."""
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200, 0x300],
        (0x200, "callees"): [0x300],
        (0x300, "callees"): [0x200],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=3, max_functions=2)

    assert result["limits"]["budget_exhausted"] is False


# --- the enums, and why they are string enums --------------------------------

def test_a_status_renders_as_the_plain_string_everywhere():
    """The reason StrEnum is backported rather than using (str, Enum).

    A bare mixin serialises correctly but renders as `BodyStatus.OK` from
    str() and f-strings, so the first log line or prompt that interpolates one
    prints the wrong thing -- and nothing fails while it does.
    """
    status = call_graph.BodyStatus.OK

    assert str(status) == "ok"
    assert f"{status}" == "ok"
    assert "{}".format(status) == "ok"
    assert status == "ok", "still compares equal to the string it replaces"


def test_a_status_survives_the_json_the_tool_sends():
    """json.dumps refuses a bare Enum, and would refuse it in the tool path
    only -- long after the collector's own tests had passed."""
    import json

    assert json.dumps({"status": call_graph.BodyStatus.FAILED}) == '{"status": "failed"}'


def test_a_relation_is_a_string_enum_too():
    assert str(call_graph.Relation.CALLER) == "caller"
    assert call_graph.Relation.for_direction("callers") is call_graph.Relation.CALLER
    assert call_graph.Relation.for_direction("callees") is call_graph.Relation.CALLEE


def test_relations_serialise_as_a_plain_list_of_strings():
    import json

    relations = [call_graph.Relation.CALLEE, call_graph.Relation.CALLER]

    assert json.dumps(relations) == '["callee", "caller"]'


# --- the neighbour keeps its own invariants ----------------------------------

def test_a_neighbour_reached_again_keeps_its_relations_unique_and_ordered():
    body = call_graph.Body("code", False, call_graph.BodyStatus.OK)
    neighbour = call_graph.Neighbour(
        ea=0x200, name="f", depth=2, body=body,
        relations=[call_graph.Relation.CALLER])

    neighbour.also_reached_as(call_graph.Relation.CALLEE, 1)
    neighbour.also_reached_as(call_graph.Relation.CALLEE, 3)

    assert neighbour.relations == ["callee", "caller"], "unique and ordered"
    assert neighbour.depth == 1, "the nearer depth wins, and later ones do not undo it"


def test_a_neighbour_renders_the_payload_the_tool_sends():
    body = call_graph.Body("int f;", True, call_graph.BodyStatus.OK)
    neighbour = call_graph.Neighbour(
        ea=0x200, name="f", depth=1, body=body,
        relations=[call_graph.Relation.CALLEE])

    assert neighbour.as_payload() == {
        "ea": "0x200",
        "name": "f",
        "relations": ["callee"],
        "depth": 1,
        "code": "int f;",
        "truncated": True,
        "status": "ok",
    }


def test_a_direction_is_named_rather_than_spelled_out():
    assert call_graph.Direction.parse("both") is call_graph.Direction.BOTH
    assert call_graph.Direction.BOTH == "both", "still the string it serialises as"


def test_an_unknown_direction_is_refused_with_the_same_message():
    import pytest

    with pytest.raises(ValueError, match="must be callers, callees or both"):
        call_graph.Direction.parse("sideways")


def test_a_relation_is_never_guessed_from_an_unknown_direction():
    """The conditional this replaced had an else, so a typo, an empty string
    and None all came back CALLEE -- a confident wrong answer."""
    import pytest

    for bad in ("sideways", "", None, "caller"):
        with pytest.raises(ValueError):
            call_graph.Relation.for_direction(bad)


def test_both_names_two_relations_so_asking_for_one_is_an_error():
    import pytest

    with pytest.raises(ValueError, match="two relations"):
        call_graph.Relation.for_direction(call_graph.Direction.BOTH)


def test_the_three_xref_parameters_agree_with_each_other():
    """They were three separate conditionals; getting one wrong queried the
    other direction and nothing said so."""
    callers = call_graph.Direction.CALLERS.xrefs
    callees = call_graph.Direction.CALLEES.xrefs

    assert callers == ("to", "from_func", "from_ea")
    assert callees == ("from", "to_func", "to_ea")
    assert set(callers) & set(callees) == set(), "no parameter shared by both"


def test_both_has_no_single_xref_query():
    import pytest

    with pytest.raises(ValueError, match="walks two ways"):
        call_graph.Direction.BOTH.xrefs


def test_neighbours_asks_for_the_direction_it_was_given(monkeypatch):
    """The parameters reaching the xref API are the direction's, not a guess."""
    asked = {}

    def fake_xrefs(**kwargs):
        asked.update(kwargs)
        return {"xrefs": []}

    monkeypatch.setattr(call_graph, "get_xrefs_unified", fake_xrefs)

    call_graph._function_neighbours(0x100, call_graph.Direction.CALLERS)
    assert (asked["direction"], asked["collapse_by"]) == ("to", "from_func")

    call_graph._function_neighbours(0x100, call_graph.Direction.CALLEES)
    assert (asked["direction"], asked["collapse_by"]) == ("from", "to_func")


def test_neighbours_refuses_a_direction_that_is_not_one(monkeypatch):
    import pytest

    monkeypatch.setattr(call_graph, "get_xrefs_unified",
                        lambda **kwargs: {"xrefs": []})

    with pytest.raises(ValueError):
        call_graph._function_neighbours(0x100, "sideways")
    with pytest.raises(ValueError, match="walks two ways"):
        call_graph._function_neighbours(0x100, call_graph.Direction.BOTH)


# --- a caller is evidence of the call, so that is the part to keep -----------

def _caller_body(prologue_lines: int, tail_lines: int, callee: str) -> str:
    """A caller whose call site sits well past its prologue."""
    return "\n".join(
        [f"  int local_{n} = {n};" for n in range(prologue_lines)]
        + [f"  result = {callee}(buffer, length, FLAG_URGENT);"]
        + [f"  cleanup_{n}();" for n in range(tail_lines)]
    )


def test_head_truncation_loses_the_one_thing_a_caller_is_evidence_of():
    """The behaviour being fixed, pinned so the fix cannot be read as noise.

    Measured over 382 caller bodies of the test binary that name their callee,
    head truncation at 600 characters kept the call site in 54.19% of them.
    """
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    head = call_graph._truncate(code, 600)

    assert head.truncated is True
    assert "sub_140005390" not in head.text


def test_a_window_keeps_the_call_site_within_the_same_budget():
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    window = call_graph._window(code, 600, "sub_140005390")

    assert window.truncated is True
    assert "sub_140005390(buffer, length, FLAG_URGENT);" in window.text
    assert len(window.text) <= 600


def test_a_window_says_that_it_elided_the_head_as_well_as_the_tail():
    """A fragment starting mid-function reads like a whole one without this."""
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    text = call_graph._window(code, 600, "sub_140005390").text

    assert text.startswith("// ... truncated ...")
    assert text.endswith("// ... truncated ...")


def test_a_window_keeps_the_lines_around_the_call_not_just_the_call():
    """Argument setup is the reason a caller is worth including at all."""
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    text = call_graph._window(code, 600, "sub_140005390").text

    assert "local_59" in text, "the lines feeding the call"
    assert "cleanup_0" in text, "and what it does with the result"


def test_a_body_that_fits_is_never_windowed():
    code = "int f(void) { return sub_140005390(); }"

    assert call_graph._window(code, 600, "sub_140005390") == (code, False)


def test_an_anchor_that_never_appears_falls_back_to_the_head():
    """An indirect call, a tail jump, a thunk: 19 of 401 bodies measured."""
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    assert call_graph._window(code, 600, "sub_DOES_NOT_APPEAR") == \
        call_graph._truncate(code, 600)


def test_no_anchor_is_the_old_behaviour_exactly():
    """A callee wants its head, and asks for it by passing no anchor."""
    code = _caller_body(prologue_lines=60, tail_lines=60, callee="sub_140005390")

    assert call_graph._window(code, 600, None) == call_graph._truncate(code, 600)


def test_the_budget_holds_even_when_the_call_site_alone_overruns_it():
    """The line is still better than the prologue, but it is still bounded."""
    code = "  int x = 1;\n" + "  r = sub_140005390(" + "a, " * 400 + "z);\n  done();"

    window = call_graph._window(code, 40, "sub_140005390")

    assert len(window.text) == 40
    assert window.truncated is True
    assert "sub_140005390" in window.text


def test_the_budget_holds_across_every_anchor_position():
    """The window grows outwards, so both ends are places to get this wrong."""
    for prologue, tail in ((0, 120), (120, 0), (60, 60), (1, 1)):
        code = _caller_body(prologue, tail, "sub_140005390")
        for budget in (20, 61, 300, 600, 5000):
            window = call_graph._window(code, budget, "sub_140005390")
            assert len(window.text) <= budget, (prologue, tail, budget)


def test_the_collector_anchors_a_caller_on_the_function_it_called(monkeypatch):
    """The wiring, not the cutting.

    `_window` can be perfect and the feature still dead if `_walk` never hands
    it an anchor -- and every unit test above would still pass. Only the real
    collector can show that a caller is cut around its call site while a callee
    is cut from the head.
    """
    bodies = {
        0x100: "int root(void) { return 0; }",
        0x200: _caller_body(prologue_lines=60, tail_lines=60, callee="function_100"),
        0x300: _caller_body(prologue_lines=60, tail_lines=60, callee="function_100"),
    }
    monkeypatch.setattr(call_graph, "resolve_func",
                        lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name",
                        lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours",
                        lambda ea, direction: {
                            (0x100, "callers"): [0x200],
                            (0x100, "callees"): [0x300],
                        }.get((ea, direction), []))
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: bodies[ea])

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8,
        max_chars_per_function=600)
    by_ea = {n["ea"]: n for n in result["neighbours"]}

    caller, callee = by_ea["0x200"], by_ea["0x300"]
    assert caller["relations"] == ["caller"]
    assert callee["relations"] == ["callee"]

    # The caller is cut around the call it makes...
    assert "function_100(buffer, length, FLAG_URGENT);" in caller["code"]
    # ...and the callee, which has no call site to keep, is cut from the head.
    assert callee["code"].startswith("  int local_0 = 0;")
    assert "function_100(" not in callee["code"]


def test_a_window_measures_itself_exactly_as_it_renders_itself():
    """`len` counts characters, `str` builds them: one fact computed twice.

    A window that measures shorter than it renders puts text over a budget
    that was checked as fitting, and the overrun appears only in the returned
    string -- never in the check that let it through. So this is asserted
    exhaustively over every window of every shape below, not sampled.
    """
    shapes = [
        ["a"],
        ["", ""],                               # empty lines still cost a newline
        ["one", "two", "three"],
        ["", "x", "", "y", ""],                 # blanks at both ends and inside
        ["  r = sub_1(a);", "", "  return r;"],
        ["éèê", "你好"],  # code points, not bytes
        ["x" * 500, "y" * 500],
        [""] * 7,
    ]
    checked = 0
    for lines in shapes:
        for first in range(len(lines)):
            for last in range(first, len(lines)):
                window = call_graph._Window(lines, first, last)
                assert len(window) == len(str(window)), (lines, first, last)
                checked += 1
    assert checked == sum(
        len(lines) * (len(lines) + 1) // 2 for lines in shapes)


def test_a_window_marks_only_the_ends_it_actually_elided():
    lines = ["a", "b", "c", "d"]

    whole = call_graph._Window(lines, 0, 3)
    assert whole.elisions == ("", "")
    assert str(whole) == "a\nb\nc\nd"

    middle = call_graph._Window(lines, 1, 2)
    assert middle.elisions == (call_graph._TRUNCATION_PREFIX,
                               call_graph._TRUNCATION_SUFFIX)

    head = call_graph._Window(lines, 0, 1)
    assert head.elisions == ("", call_graph._TRUNCATION_SUFFIX)

    tail = call_graph._Window(lines, 2, 3)
    assert tail.elisions == (call_graph._TRUNCATION_PREFIX, "")
