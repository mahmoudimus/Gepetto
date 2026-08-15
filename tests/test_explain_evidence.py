from gepetto.ida import handlers
from types import SimpleNamespace


def test_explain_evidence_uses_a_bounded_call_graph_slice(monkeypatch):
    seen = {}

    def collect(ea, **limits):
        seen["ea"] = ea
        seen["limits"] = limits
        return {
            "neighbours": [
                {
                    "ea": "0x200",
                    "name": "caller_name",
                    "relation": "caller",
                    "depth": 1,
                    "code": "deadline = get_time_ns();",
                    "truncated": False,
                }
            ]
        }

    monkeypatch.setattr(handlers, "collect_call_graph_context", collect, raising=False)

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

    monkeypatch.setattr(handlers, "collect_call_graph_context", collect, raising=False)

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
