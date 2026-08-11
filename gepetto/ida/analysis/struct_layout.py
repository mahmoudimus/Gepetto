"""Derive a struct layout from how a pointer is actually used.

The layout of an undeclared struct is not a matter of opinion: the offsets, the
access widths, and whether each field is read or written are all in the ctree.
Asking a model to invent them produces plausible fiction. So this collects the
evidence mechanically and leaves the model the part it is good at -- deciding
what the fields mean and what to call them.

Two ideas are borrowed from prior art:

* HexRaysPyTools' deep scan: a struct pointer handed to a callee accumulates
  the fields discovered *there* too, because a single function almost never
  touches the whole structure.
* Its scoring of competing candidates: when one offset is read as both an int
  and a pointer, the alternatives are ranked rather than resolved first-wins.
"""

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idaapi

from gepetto.ida.utils.thread_helpers import hexrays_available, run_on_main_thread

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FUNCTIONS = 12

# Access kinds, in the order we prefer them when two disagree about a field.
# An explicit member reference tells us more than a hand-rolled dereference.
_KIND_RANK = {"memptr": 3, "memref": 3, "deref": 2, "index": 1}


class _Aliases:
    """Which locals must be the same type as each other.

    Borrowed from AutoStruct. Without it `v5 = a1; v5->field_20 = x` loses the
    field, because v5 is a different lvar; with it the two are one group. It
    also keeps things apart: `v5 = a1->field_10` unions nothing, so a nested
    pointer's fields never merge into its parent's layout.
    """

    def __init__(self):
        self._parent = {}

    def find(self, item):
        self._parent.setdefault(item, item)
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, a, b):
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a


class _AliasVisitor(ida_hexrays.ctree_visitor_t):
    """Union locals joined by a plain assignment, and nothing else."""

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.aliases = _Aliases()

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_asg:
            lhs, rhs = _strip_casts(expr.x), _strip_casts(expr.y)
            if (lhs is not None and rhs is not None
                    and lhs.op == ida_hexrays.cot_var and rhs.op == ida_hexrays.cot_var):
                self.aliases.union(lhs.v.idx, rhs.v.idx)
        return 0


def _pointer_size():
    return 8 if idaapi.inf_is_64bit() else 4


def _read_pointer(ea):
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def read_vtable(ea, max_methods=256):
    """Walk a vtable: consecutive pointers into code.

    Stops at the first slot that is not code, and also when another data
    reference points at the next slot -- that is where a different vtable
    begins, and running past it invents methods that belong to someone else.
    """
    methods = []
    cursor = ea
    size = _pointer_size()
    while len(methods) < max_methods:
        try:
            pointer = _read_pointer(cursor)
        except Exception:
            break
        if not pointer or pointer == idaapi.BADADDR:
            break
        function = ida_funcs.get_func(pointer)
        is_code = function is not None or idaapi.is_code(idaapi.get_flags(pointer))
        if not is_code:
            break
        methods.append(
            {
                "slot": len(methods),
                "offset_hex": hex(len(methods) * size),
                "ea": hex(pointer),
                "name": ida_funcs.get_func_name(pointer) or ida_name.get_ea_name(pointer) or "",
            }
        )
        cursor += size
        if idaapi.get_first_dref_to(cursor) != idaapi.BADADDR:
            break  # another vtable starts here
    return methods


# --- matching against types that already exist -------------------------------
#
# Ported from hrtng's recognize_shape/struct_matches. Deriving a fresh struct
# every time means meeting the same type in thirty functions and manufacturing
# thirty near-identical definitions, when the answer is already in Local Types.


def _members_of(tif):
    """Byte offset -> (size, type name, tinfo) for one struct.

    udm_t reports offsets and sizes in *bits*; everything else here is bytes.
    """
    details = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(details):
        return None
    members = {}
    for member in details:
        members[member.offset // 8] = (
            member.size // 8,
            member.type.dstr() if member.type is not None else "",
            member.type,
        )
    return members


def iter_local_structs(max_ordinals=4096):
    """Every struct in the local type library."""
    try:
        limit = min(ida_typeinf.get_ordinal_limit(), max_ordinals)
    except Exception:
        return
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_numbered_type(ordinal, ida_typeinf.BTF_STRUCT, True):
                continue
            if not tif.is_struct():
                continue
        except Exception:
            continue
        yield ordinal, tif


def _size_fits(access_size, member_size, member_type):
    """Whether an access of this width is consistent with this member.

    A union member accepts anything, and an access narrower than the member
    may be reaching the first field of a nested struct, so that is unwound
    rather than rejected -- both cases hrtng handles and a naive equality
    check gets wrong.
    """
    if not access_size or not member_size:
        return True  # unknown width proves nothing either way
    if access_size == member_size:
        return True
    try:
        if member_type is not None and member_type.is_union():
            return True
        current = member_type
        while (current is not None and current.is_struct()
               and current.get_size() > access_size):
            inner = _members_of(current)
            if not inner or 0 not in inner:
                return False
            size, _name, current = inner[0]
            if size == access_size:
                return True
    except Exception:
        return False
    return False


def match_existing_structs(layout, max_results=10):
    """Types already defined that are consistent with the observed accesses."""
    observed = [f for f in layout.get("fields", []) if not f.get("padding")]
    if not observed:
        return []

    matches = []
    for ordinal, tif in iter_local_structs():
        members = _members_of(tif)
        if not members:
            continue
        struct_size = tif.get_size()
        ok = True
        for field in observed:
            offset, access_size = field["offset"], field["size"]
            # A whole-struct-sized read at 0 may be the object itself.
            if offset == 0 and access_size and struct_size == access_size:
                continue
            if offset not in members:
                ok = False
                break
            member_size, _name, member_type = members[offset]
            if not _size_fits(access_size, member_size, member_type):
                ok = False
                break
        if ok:
            matches.append(
                {
                    "name": tif.get_type_name() or f"ordinal_{ordinal}",
                    "ordinal": ordinal,
                    "size": struct_size,
                    "members": len(members),
                    "matched_fields": len(observed),
                }
            )
        if len(matches) >= max_results:
            break
    # Fewest members first: the tightest type that still explains the evidence.
    matches.sort(key=lambda m: (m["members"], m["size"]))
    return matches


def find_structs_by_size(size):
    """Local types whose total size is exactly this."""
    found = []
    for ordinal, tif in iter_local_structs():
        if tif.get_size() == size:
            found.append({"name": tif.get_type_name() or f"ordinal_{ordinal}",
                          "ordinal": ordinal, "size": size})
    return found


def find_structs_by_offset(offset):
    """Local types with a member at exactly this byte offset."""
    found = []
    for ordinal, tif in iter_local_structs():
        members = _members_of(tif)
        if members and offset in members:
            member_size, type_name, _t = members[offset]
            found.append({
                "name": tif.get_type_name() or f"ordinal_{ordinal}",
                "ordinal": ordinal,
                "member_size": member_size,
                "member_type": type_name,
            })
    return found


class _Access:
    __slots__ = ("offset", "size", "type_name", "kind", "is_write", "ea", "func")

    def __init__(self, offset, size, type_name, kind, is_write, ea, func):
        self.offset = offset
        self.size = size
        self.type_name = type_name
        self.kind = kind
        self.is_write = is_write
        self.ea = ea
        self.func = func


def _type_name(tif):
    try:
        name = tif.dstr() if tif is not None else None
    except Exception:
        name = None
    return name or "void"


def _type_size(tif):
    try:
        size = tif.get_size() if tif is not None else 0
    except Exception:
        size = 0
    return size if size and size != idaapi.BADSIZE else 0


def _strip_casts(expr):
    while expr is not None and expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


class _LayoutVisitor(ida_hexrays.ctree_visitor_t):
    """Collect every access made through one local variable.

    ``target`` is the lvar index whose accesses we care about; calls that pass
    it on are recorded so the caller can follow them.
    """

    def __init__(self, cfunc, target_index, aliases=None):
        super().__init__(ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.aliases = aliases or _Aliases()
        self.target = self.aliases.find(target_index)
        self.accesses = []
        self.forwarded = []  # (callee_ea, argument_index)
        self.vtable_stores = []  # addresses assigned to *target
        self.virtual_calls = []  # slot offsets called through *target

    # -- helpers

    def _is_target(self, expr):
        expr = _strip_casts(expr)
        if expr is None or expr.op != ida_hexrays.cot_var:
            return False
        return self.aliases.find(expr.v.idx) == self.target

    def _is_vtable_slot(self, expr):
        """Match *(*target + N), the shape of a virtual call. Returns N."""
        expr = _strip_casts(expr)
        if expr is None or expr.op != ida_hexrays.cot_ptr:
            return None
        inner = _strip_casts(expr.x)
        if inner is None:
            return None
        if inner.op == ida_hexrays.cot_add:
            base, index = _strip_casts(inner.x), inner.y
            if (base is not None and base.op == ida_hexrays.cot_ptr
                    and self._is_target(base.x) and index.op == ida_hexrays.cot_num):
                return index.numval()
            return None
        if inner.op == ida_hexrays.cot_ptr and self._is_target(inner.x):
            return 0
        return None

    def _written(self, expr):
        """True when this expression is the destination of an assignment."""
        parent = self.parent_expr()
        if parent is None:
            return False
        if parent.op == ida_hexrays.cot_asg:
            return parent.x is expr
        # Compound assignments (+=, |=, ...) both read and write; count them as
        # writes because they prove the field is not read-only.
        return ida_hexrays.cot_asgadd <= parent.op <= ida_hexrays.cot_asgumod

    def _record(self, offset, expr, kind):
        if offset is None or offset < 0:
            return  # negative offsets are a different animal (CONTAINING_RECORD)
        self.accesses.append(
            _Access(
                offset=int(offset),
                size=_type_size(expr.type),
                type_name=_type_name(expr.type),
                kind=kind,
                is_write=self._written(expr),
                ea=expr.ea if expr.ea != idaapi.BADADDR else self.cfunc.entry_ea,
                func=ida_funcs.get_func_name(self.cfunc.entry_ea) or "",
            )
        )

    # -- traversal

    def visit_expr(self, expr):
        op = expr.op

        # x->field / x.field: IDA already knows the offset.
        if op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            if self._is_target(expr.x):
                kind = "memptr" if op == ida_hexrays.cot_memptr else "memref"
                self._record(expr.m, expr, kind)

        # *(T *)(x + N), and plain *x meaning offset 0.
        elif op == ida_hexrays.cot_ptr:
            inner = _strip_casts(expr.x)
            if inner is not None and inner.op == ida_hexrays.cot_add:
                base, index = inner.x, inner.y
                if self._is_target(base) and index.op == ida_hexrays.cot_num:
                    self._record(index.numval(), expr, "deref")
            elif self._is_target(inner):
                self._record(0, expr, "deref")

        # x[N]: a constant index is a field, a variable index is an array.
        elif op == ida_hexrays.cot_idx:
            if self._is_target(expr.x) and expr.y.op == ida_hexrays.cot_num:
                element = _type_size(expr.type) or 1
                self._record(expr.y.numval() * element, expr, "index")

        # *target = &off_140xxx: the object's vtable being installed.
        elif op == ida_hexrays.cot_asg:
            destination = _strip_casts(expr.x)
            if (destination is not None and destination.op == ida_hexrays.cot_ptr
                    and self._is_target(destination.x)):
                source = _strip_casts(expr.y)
                if source is not None and source.op == ida_hexrays.cot_ref:
                    source = _strip_casts(source.x)
                if source is not None and source.op == ida_hexrays.cot_obj:
                    self.vtable_stores.append(source.obj_ea)

        # Passing the pointer on: remember where, so the scan can follow.
        elif op == ida_hexrays.cot_call:
            slot = self._is_vtable_slot(expr.x)
            if slot is not None:
                self.virtual_calls.append(int(slot))
            callee = _strip_casts(expr.x)
            if callee is not None and callee.op == ida_hexrays.cot_obj:
                for position, argument in enumerate(expr.a or []):
                    if self._is_target(argument):
                        self.forwarded.append((callee.obj_ea, position))

        return 0


def _scan_one(func_ea, argument_index):
    """Accesses made through one argument of one function, plus where it goes."""
    empty = ([], [], [], [])
    function = ida_funcs.get_func(func_ea)
    if function is None:
        return empty
    try:
        cfunc = ida_hexrays.decompile(function)
    except Exception:
        return empty
    if cfunc is None:
        return empty

    lvars = cfunc.get_lvars()
    # Arguments come first in the lvar list, in order.
    arguments = [i for i, lvar in enumerate(lvars) if lvar.is_arg_var]
    if argument_index >= len(arguments):
        return empty

    alias_pass = _AliasVisitor()
    alias_pass.apply_to(cfunc.body, None)

    visitor = _LayoutVisitor(cfunc, arguments[argument_index], alias_pass.aliases)
    visitor.apply_to(cfunc.body, None)
    return visitor.accesses, visitor.forwarded, visitor.vtable_stores, visitor.virtual_calls


def _resolve(accesses):
    """Pick one type per offset, keeping the alternatives as evidence.

    Ranked by how the field was reached, then by how often, then by width: an
    explicit member reference beats a hand-rolled dereference, and a field seen
    fifteen times as a pointer is not redefined by one stray byte read.
    """
    by_offset = {}
    for access in accesses:
        by_offset.setdefault(access.offset, []).append(access)

    fields = []
    for offset in sorted(by_offset):
        group = by_offset[offset]
        counts = {}
        for access in group:
            key = (access.type_name, access.size)
            counts[key] = counts.get(key, 0) + 1

        def rank(item):
            (type_name, size), count = item
            best_kind = max(
                _KIND_RANK.get(a.kind, 0) for a in group
                if (a.type_name, a.size) == (type_name, size)
            )
            return (best_kind, count, size)

        (chosen_type, chosen_size), _count = max(counts.items(), key=rank)
        alternatives = sorted(
            {f"{name} ({size} bytes)" for (name, size), _ in counts.items()
             if (name, size) != (chosen_type, chosen_size)}
        )
        fields.append(
            {
                "offset": offset,
                "offset_hex": hex(offset),
                "size": chosen_size,
                "type": chosen_type,
                "reads": sum(1 for a in group if not a.is_write),
                "writes": sum(1 for a in group if a.is_write),
                "seen_in": sorted({a.func for a in group if a.func}),
                "evidence": sorted({hex(a.ea) for a in group})[:8],
                "other_types_seen": alternatives,
            }
        )
    return fields


def _add_padding(fields):
    """Insert explicit gaps, so what was never touched is visibly unknown."""
    padded = []
    cursor = 0
    for field in fields:
        if field["offset"] > cursor:
            padded.append(
                {
                    "offset": cursor,
                    "offset_hex": hex(cursor),
                    "size": field["offset"] - cursor,
                    "type": "_BYTE",
                    "padding": True,
                    "note": "never accessed by the code scanned",
                }
            )
        padded.append(field)
        cursor = max(cursor, field["offset"] + (field["size"] or 1))
    return padded


def collect_layout(ea=None, argument_index=0, max_depth=DEFAULT_MAX_DEPTH,
                   max_functions=DEFAULT_MAX_FUNCTIONS):
    """Derive a struct layout from how one pointer argument is used.

    Follows the pointer into callees it is handed to, breadth first, because a
    single function rarely touches the whole structure.
    """
    if not hexrays_available():
        raise RuntimeError("Hex-Rays is required to derive a struct layout.")

    root = ida_funcs.get_func(ea if ea is not None else idaapi.get_screen_ea())
    if root is None:
        raise ValueError("No function at the requested address.")

    def _work():
        accesses = []
        scanned = []
        vtable_stores = []
        virtual_calls = set()
        seen = set()
        frontier = [(root.start_ea, argument_index, 0)]

        while frontier and len(scanned) < max_functions:
            func_ea, position, depth = frontier.pop(0)
            if (func_ea, position) in seen:
                continue
            seen.add((func_ea, position))

            found, forwarded, stores, calls = _scan_one(func_ea, position)
            accesses.extend(found)
            vtable_stores.extend(stores)
            virtual_calls.update(calls)
            scanned.append(
                {
                    "function": ida_funcs.get_func_name(func_ea) or hex(func_ea),
                    "ea": hex(func_ea),
                    "argument": position,
                    "depth": depth,
                    "accesses": len(found),
                }
            )
            if depth < max_depth:
                frontier.extend(
                    (callee, index, depth + 1) for callee, index in forwarded
                )

        vtable = None
        for store in vtable_stores:
            methods = read_vtable(store)
            if methods:
                vtable = {"ea": hex(store), "methods": methods}
                break
        return accesses, scanned, vtable, sorted(virtual_calls)

    accesses, scanned, vtable, virtual_calls = run_on_main_thread(_work)
    fields = _resolve(accesses)
    laid_out = _add_padding(fields)
    size = max((f["offset"] + (f["size"] or 1) for f in fields), default=0)

    return {
        "root": {
            "function": ida_funcs.get_func_name(root.start_ea) or hex(root.start_ea),
            "ea": hex(root.start_ea),
            "argument": argument_index,
        },
        "inferred_size": size,
        "fields": laid_out,
        "scanned_functions": scanned,
        "matching_types": run_on_main_thread(
            lambda: match_existing_structs({"fields": laid_out})),
        "vtable": vtable,
        "virtual_call_slots": [
            {"slot_offset_hex": hex(offset), "slot": offset // _pointer_size()}
            for offset in virtual_calls
        ],
        "limits": {"max_depth": max_depth, "max_functions": max_functions},
        "note": (
            "Check matching_types before declaring anything new: a type that "
            "already explains these accesses is almost always the right answer. "
            "Offsets, widths and read/write counts are observed, not guessed. "
            "Gaps marked padding were never accessed by the functions scanned, "
            "so their contents are unknown rather than empty."
        ),
    }


def to_c_declaration(layout, name="struct_from_gepetto"):
    """Render a layout as a C struct, for review or for declare_c_type."""
    lines = []
    vtable = layout.get("vtable")
    if vtable:
        lines.append(f"// vtable at {vtable['ea']}, {len(vtable['methods'])} methods:")
        for method in vtable["methods"][:12]:
            lines.append(f"//   [{method['slot']}] {method['name'] or method['ea']}")
        if len(vtable["methods"]) > 12:
            lines.append(f"//   ... {len(vtable['methods']) - 12} more")
    lines += [f"struct {name}", "{"]
    for field in layout["fields"]:
        offset = field["offset_hex"]
        if field.get("padding"):
            lines.append(f"    _BYTE gap_{offset[2:]}[{field['size']}];  // {offset}: never accessed")
            continue
        member = f"field_{offset[2:]}"
        access = f"r{field['reads']}/w{field['writes']}"
        lines.append(f"    {field['type']} {member};  // {offset}, {access}")
    lines.append("};")
    return "\n".join(lines)
