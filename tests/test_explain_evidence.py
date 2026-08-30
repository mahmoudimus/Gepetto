from gepetto.ida import handlers
from types import SimpleNamespace

from gepetto.ida.call_graph import (Body, BodyStatus, CallGraphSlice, Direction,
                                    Limits, Neighbour, Root)


def _neighbour(ea, name, relations, depth=1, code="x"):
    """A real Neighbour, so these tests cannot drift from the producer."""
    return Neighbour(ea=ea, name=name, depth=depth,
                     body=Body(code, False, BodyStatus.OK),
                     relations=list(relations))


def _slice(*neighbours):
    return CallGraphSlice(
        root=Root(0x100, "root", Body("int root(void);", False, BodyStatus.OK)),
        neighbours=list(neighbours),
        limits=Limits(Direction.BOTH, 1, 4, len(neighbours), False),
    )


def test_explain_evidence_uses_a_bounded_call_graph_slice(monkeypatch):
    seen = {}

    def collect(ea, **limits):
        seen["ea"] = ea
        seen["limits"] = limits
        return _slice(_neighbour(0x200, "caller_name", ["caller"],
                                 code="deadline = get_time_ns();"))

    monkeypatch.setattr(handlers, "collect_call_graph_slice", collect)

    evidence = handlers._collect_explain_call_graph_context(0x100)

    assert seen == {
        "ea": 0x100,
        "limits": {
            "direction": "both",
            "max_depth": 1,
            "max_functions": 4,
            "max_chars_per_function": 600,
        },
    }
    assert "caller_name" in evidence
    assert "deadline = get_time_ns();" in evidence
    assert "bounded" in evidence.lower()


def test_explain_evidence_is_optional_when_collection_fails(monkeypatch, capsys):
    def collect(*_args, **_kwargs):
        raise RuntimeError("no decompiler")

    # No raising=False: patching a name this module does not have is how a
    # rename goes unnoticed, and this test then exercises the real collector.
    monkeypatch.setattr(handlers, "collect_call_graph_slice", collect)

    assert handlers._collect_explain_call_graph_context(0x100) == ""
    assert "call-graph evidence unavailable" in capsys.readouterr().out


def test_explain_handler_sends_relationship_evidence_to_the_model(monkeypatch):
    requests = []

    monkeypatch.setattr(handlers.idaapi, "get_screen_ea", lambda: 0x100)
    monkeypatch.setattr(handlers.ida_hexrays, "decompile", lambda _ea: "int helper(void)")
    monkeypatch.setattr(handlers.ida_hexrays, "get_widget_vdui", lambda _widget: "view")
    monkeypatch.setattr(handlers.gepetto.config, "get_localization_locale", lambda: "en_US")
    monkeypatch.setattr(handlers, "_collect_explain_call_graph_context", lambda _ea: "EVIDENCE")
    monkeypatch.setattr(
        handlers.gepetto.config,
        "model",
        SimpleNamespace(query_model_async=lambda prompt, _callback: requests.append(prompt)),
    )
    monkeypatch.setattr(
        handlers,
        "STATUS_PANEL",
        SimpleNamespace(log_request_started=lambda: "started"),
    )

    assert handlers.ExplainHandler().activate(SimpleNamespace(widget=object())) == 1
    assert len(requests) == 1
    assert "EVIDENCE" in requests[0]
    assert "observed role" in requests[0]


def test_a_neighbour_reached_both_ways_says_so_in_the_prompt():
    """The collector aggregates the two relations onto one neighbour; the
    prompt should carry both rather than picking one."""
    from gepetto.ida.handlers import _format_explain_call_graph_context

    text = _format_explain_call_graph_context(
        _slice(_neighbour(0x140001000, "helper", ["callee", "caller"],
                          code="int helper(void);")))

    assert "[callee, caller, depth 1] helper (0x140001000)" in text


def test_a_neighbour_with_no_relations_is_still_rendered():
    from gepetto.ida.handlers import _format_explain_call_graph_context

    text = _format_explain_call_graph_context(
        _slice(_neighbour(0x1, "helper", [])))

    assert "[neighbour, depth 1] helper (0x1)" in text


def test_the_formatter_reads_what_the_collector_actually_produces(monkeypatch):
    """The contract test that was missing.

    Every other test here hands the formatter a neighbour it built itself, so
    when the collector renamed `relation` to `relations` they all kept passing
    while the prompt silently labelled every neighbour "neighbour". A fake
    cannot detect drift from the thing it is standing in for; only the real
    producer can.
    """
    from types import SimpleNamespace

    from gepetto.ida import call_graph
    from gepetto.ida.handlers import _format_explain_call_graph_context

    monkeypatch.setattr(call_graph, "resolve_func",
                        lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name",
                        lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours",
                        lambda ea, direction: {
                            (0x100, "callers"): [0x200],
                            (0x100, "callees"): [0x200, 0x300],
                        }.get((ea, direction), []))
    # The collector's own type, not a look-alike tuple: a fake that rebuilds
    # the shape by hand stops matching the moment a field is added.
    monkeypatch.setattr(call_graph, "_decompiled_body",
                        lambda ea, _budget, _anchor=None: call_graph.Body(
                            f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    context = call_graph.collect_call_graph_slice(
        0x100, direction="both", max_depth=1, max_functions=8)
    text = _format_explain_call_graph_context(context)

    # 0x200 is reached both ways; 0x300 only as a callee.
    assert "[callee, caller, depth 1] function_200 (0x200)" in text
    assert "[callee, depth 1] function_300 (0x300)" in text
    assert "[neighbour," not in text, "a placeholder means no relation arrived"
