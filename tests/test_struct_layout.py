"""Struct layout inference: the parts that are pure logic.

The ctree walking needs a database and is exercised against the test binary
separately; what is unit-testable here is the reasoning applied to whatever the
walk collects -- grouping, conflict resolution, gaps, and rendering.
"""

import pytest

from gepetto.ida.analysis import struct_layout as SL


def access(offset, size, type_name, kind="memptr", is_write=False, ea=0x401000, func="f"):
    return SL._Access(offset, size, type_name, kind, is_write, ea, func)


# --- alias grouping ---------------------------------------------------------

def test_aliases_are_transitive():
    a = SL._Aliases()
    a.union(1, 2)
    a.union(2, 3)
    assert a.find(1) == a.find(3)


def test_unrelated_variables_stay_apart():
    a = SL._Aliases()
    a.union(1, 2)
    assert a.find(1) != a.find(7)


def test_an_unseen_variable_is_its_own_group():
    assert SL._Aliases().find(42) == 42


# --- conflict resolution ----------------------------------------------------

def test_a_single_access_becomes_a_field():
    fields = SL._resolve([access(0x10, 8, "_QWORD")])
    assert fields[0]["offset_hex"] == "0x10"
    assert fields[0]["type"] == "_QWORD"
    assert fields[0]["reads"] == 1 and fields[0]["writes"] == 0


def test_reads_and_writes_are_counted_separately():
    fields = SL._resolve([
        access(0, 4, "int"),
        access(0, 4, "int", is_write=True),
        access(0, 4, "int", is_write=True),
    ])
    assert (fields[0]["reads"], fields[0]["writes"]) == (1, 2)


def test_an_explicit_member_beats_a_hand_rolled_dereference():
    # Same offset, same count: the access that carried real type information wins.
    fields = SL._resolve([
        access(8, 8, "_QWORD", kind="deref"),
        access(8, 4, "int", kind="memptr"),
    ])
    assert fields[0]["type"] == "int"


def test_the_more_frequent_type_wins_within_the_same_kind():
    accesses = [access(8, 8, "_QWORD") for _ in range(5)] + [access(8, 1, "_BYTE")]
    fields = SL._resolve(accesses)
    assert fields[0]["type"] == "_QWORD"


def test_the_losing_candidates_are_kept_as_evidence():
    # The model should get to argue for the alternative, not never learn of it.
    accesses = [access(8, 8, "_QWORD") for _ in range(5)] + [access(8, 1, "_BYTE")]
    fields = SL._resolve(accesses)
    assert any("_BYTE" in alternative for alternative in fields[0]["other_types_seen"])


def test_fields_come_back_in_offset_order():
    fields = SL._resolve([access(0x20, 8, "a"), access(0, 4, "b"), access(0x10, 4, "c")])
    assert [f["offset"] for f in fields] == [0, 0x10, 0x20]


def test_the_functions_a_field_was_seen_in_are_recorded():
    fields = SL._resolve([
        access(0, 4, "int", func="caller"),
        access(0, 4, "int", func="callee"),
    ])
    assert fields[0]["seen_in"] == ["callee", "caller"]


# --- gaps -------------------------------------------------------------------

def test_untouched_bytes_become_an_explicit_gap():
    padded = SL._add_padding(SL._resolve([access(0, 2, "_WORD"), access(0x10, 8, "_QWORD")]))
    gaps = [f for f in padded if f.get("padding")]
    assert len(gaps) == 1
    assert gaps[0]["offset"] == 2 and gaps[0]["size"] == 0xE


def test_adjacent_fields_produce_no_gap():
    padded = SL._add_padding(SL._resolve([access(0, 8, "_QWORD"), access(8, 8, "_QWORD")]))
    assert not any(f.get("padding") for f in padded)


def test_a_gap_says_unknown_rather_than_empty():
    padded = SL._add_padding(SL._resolve([access(0, 1, "_BYTE"), access(0x10, 8, "_QWORD")]))
    gap = next(f for f in padded if f.get("padding"))
    assert "never accessed" in gap["note"]


# --- rendering --------------------------------------------------------------

def test_the_declaration_is_well_formed_c():
    layout = {"fields": SL._add_padding(SL._resolve([access(0, 8, "_QWORD"), access(0x10, 4, "int")]))}
    declaration = SL.to_c_declaration(layout, "thing_t")
    assert declaration.startswith("struct thing_t")
    assert declaration.rstrip().endswith("};")
    assert "_QWORD field_0;" in declaration
    assert "int field_10;" in declaration


def test_the_declaration_carries_the_vtable_when_one_was_found():
    layout = {
        "fields": SL._add_padding(SL._resolve([access(0, 8, "_QWORD")])),
        "vtable": {"ea": "0x140d5610", "methods": [
            {"slot": 0, "name": "Release", "ea": "0x401000"},
            {"slot": 1, "name": "", "ea": "0x401100"},
        ]},
    }
    declaration = SL.to_c_declaration(layout)
    assert "// vtable at 0x140d5610, 2 methods:" in declaration
    assert "[0] Release" in declaration
    # A nameless slot still has to be identifiable.
    assert "[1] 0x401100" in declaration


def test_read_write_counts_reach_the_declaration():
    layout = {"fields": SL._resolve([access(0, 4, "int"), access(0, 4, "int", is_write=True)])}
    assert "r1/w1" in SL.to_c_declaration(layout)


# --- size compatibility rule (hrtng's struct_matches) ------------------------

class _FakeType:
    """Enough of tinfo_t for the width rule; the IDA-backed paths are tested
    against the real type library separately."""

    def __init__(self, size, union=False, struct=False, first=None):
        self._size, self._union, self._struct, self._first = size, union, struct, first

    def get_size(self):
        return self._size

    def is_union(self):
        return self._union

    def is_struct(self):
        return self._struct


def test_an_exact_width_match_fits():
    assert SL._size_fits(4, 4, _FakeType(4))


def test_a_mismatched_width_does_not_fit():
    assert not SL._size_fits(4, 8, _FakeType(8))


def test_a_union_member_accepts_any_width():
    # A union's members vary, so the access width proves nothing against it.
    assert SL._size_fits(1, 8, _FakeType(8, union=True))


def test_an_unknown_width_is_not_treated_as_a_conflict():
    assert SL._size_fits(0, 8, _FakeType(8))
    assert SL._size_fits(4, 0, _FakeType(0))


def test_a_narrow_access_may_reach_a_nested_struct_first_member(monkeypatch):
    # 4 bytes read at the offset of a 16-byte struct whose first member is 4
    # bytes: reaching into the nested type, not a contradiction.
    inner = _FakeType(4)
    outer = _FakeType(16, struct=True)
    monkeypatch.setattr(SL, "_members_of", lambda t: {0: (4, "int", inner)})
    assert SL._size_fits(4, 16, outer)


def test_a_narrow_access_into_a_struct_that_does_not_start_that_way_fails(monkeypatch):
    outer = _FakeType(16, struct=True)
    monkeypatch.setattr(SL, "_members_of", lambda t: {0: (8, "_QWORD", _FakeType(8))})
    assert not SL._size_fits(4, 16, outer)


def test_matching_requires_at_least_one_observed_field():
    assert SL.match_existing_structs({"fields": []}) == []
    assert SL.match_existing_structs({"fields": [{"offset": 0, "size": 4, "padding": True}]}) == []


# --- applying the declared type back -----------------------------------------

def test_retyping_reports_an_error_when_the_type_is_not_declared(monkeypatch):
    # Declaring must happen first; silently doing nothing would look like success.
    monkeypatch.setattr(SL, "pointer_to", lambda name: None)
    result = SL.apply_type_to_scanned({"scanned_functions": [{"ea": "0x401000"}]}, "nope_t")
    assert result["applied"] == []
    assert "not found" in result["error"]


def test_retyping_skips_entries_with_no_usable_address(monkeypatch):
    monkeypatch.setattr(SL, "pointer_to", lambda name: object())
    result = SL.apply_type_to_scanned(
        {"scanned_functions": [{"function": "f"}, {"ea": "not-hex"}]}, "thing_t")
    assert result["applied"] == [] and result["failed"] == []


def test_retyping_a_layout_with_nothing_scanned_is_harmless(monkeypatch):
    monkeypatch.setattr(SL, "pointer_to", lambda name: object())
    assert SL.apply_type_to_scanned({"scanned_functions": []}, "thing_t") == {
        "applied": [], "failed": []}
