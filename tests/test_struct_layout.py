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
