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

import ida_funcs
import ida_hexrays
import idaapi

from gepetto.ida.utils.thread_helpers import hexrays_available, run_on_main_thread

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FUNCTIONS = 12

# Access kinds, in the order we prefer them when two disagree about a field.
# An explicit member reference tells us more than a hand-rolled dereference.
_KIND_RANK = {"memptr": 3, "memref": 3, "deref": 2, "index": 1}


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

    def __init__(self, cfunc, target_index):
        super().__init__(ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.target = target_index
        self.accesses = []
        self.forwarded = []  # (callee_ea, argument_index)

    # -- helpers

    def _is_target(self, expr):
        expr = _strip_casts(expr)
        return expr is not None and expr.op == ida_hexrays.cot_var and expr.v.idx == self.target

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

        # Passing the pointer on: remember where, so the scan can follow.
        elif op == ida_hexrays.cot_call:
            callee = _strip_casts(expr.x)
            if callee is not None and callee.op == ida_hexrays.cot_obj:
                for position, argument in enumerate(expr.a or []):
                    if self._is_target(argument):
                        self.forwarded.append((callee.obj_ea, position))

        return 0


def _scan_one(func_ea, argument_index):
    """Accesses made through one argument of one function, plus where it goes."""
    function = ida_funcs.get_func(func_ea)
    if function is None:
        return [], []
    try:
        cfunc = ida_hexrays.decompile(function)
    except Exception:
        return [], []
    if cfunc is None:
        return [], []

    lvars = cfunc.get_lvars()
    # Arguments come first in the lvar list, in order.
    arguments = [i for i, lvar in enumerate(lvars) if lvar.is_arg_var]
    if argument_index >= len(arguments):
        return [], []

    visitor = _LayoutVisitor(cfunc, arguments[argument_index])
    visitor.apply_to(cfunc.body, None)
    return visitor.accesses, visitor.forwarded


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
        seen = set()
        frontier = [(root.start_ea, argument_index, 0)]

        while frontier and len(scanned) < max_functions:
            func_ea, position, depth = frontier.pop(0)
            if (func_ea, position) in seen:
                continue
            seen.add((func_ea, position))

            found, forwarded = _scan_one(func_ea, position)
            accesses.extend(found)
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
        return accesses, scanned

    accesses, scanned = run_on_main_thread(_work)
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
        "limits": {"max_depth": max_depth, "max_functions": max_functions},
        "note": (
            "Offsets, widths and read/write counts are observed, not guessed. "
            "Gaps marked padding were never accessed by the functions scanned, "
            "so their contents are unknown rather than empty."
        ),
    }


def to_c_declaration(layout, name="struct_from_gepetto"):
    """Render a layout as a C struct, for review or for declare_c_type."""
    lines = [f"struct {name}", "{"]
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
