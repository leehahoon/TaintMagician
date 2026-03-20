from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

from z3 import And, BoolSort, Fixedpoint, IntSort, Function, Ints, sat

from constraint import Facts, IdMapper, func_ids, var_ids


# ----------------------------
# Helpers: ID mapping (same as extractor-facing names)
# ----------------------------

def fid(func_name: str) -> int:
    return func_ids.get(func_name)


def vid(var_key: str) -> int:
    return var_ids.get(var_key)


# ----------------------------
# Packed Node(Int): per-solve maps (addr, func_id, ssa_id) -> unique Int
# ----------------------------

_vpack: IdMapper | None = None
_mpack: IdMapper | None = None


def _reset_node_packs() -> None:
    global _vpack, _mpack
    _vpack = IdMapper()
    _mpack = IdMapper()


def pack_v(addr: int, func_name: str, var_key: str) -> int:
    """Value SSA node: (addr, func_id, var_id) -> packed Int."""
    assert _vpack is not None
    fi, xi = fid(func_name), vid(var_key)
    return _vpack.get(f"v:{addr}:{fi}:{xi}")


def pack_m(addr: int, func_name: str, mem_key: str) -> int:
    """Memory SSA node: (addr, func_id, mem_id) -> packed Int."""
    assert _mpack is not None
    fi, mi = fid(func_name), vid(mem_key)
    return _mpack.get(f"m:{addr}:{fi}:{mi}")


def _mem_version_ids(func_name: str, mem_key: str) -> Tuple[int, int]:
    return fid(func_name), vid(mem_key)


# ----------------------------
# Prune graph (logical SSA nodes; not Z3 pack ids)
# ----------------------------

GraphNode = Tuple[str, int, str, str]  # ("V"|"M", addr, func, name)


def _gn_v(addr: int, func: str, var: str) -> GraphNode:
    return ("V", addr, func, var)


def _gn_m(addr: int, func: str, mem: str) -> GraphNode:
    return ("M", addr, func, mem)


def _bfs(starts: Iterable[GraphNode], adj: Dict[GraphNode, Set[GraphNode]]) -> Set[GraphNode]:
    seen: Set[GraphNode] = set()
    work = list(starts)
    for n in work:
        seen.add(n)
    i = 0
    while i < len(work):
        cur = work[i]
        i += 1
        for nxt in adj.get(cur, ()):
            if nxt in seen:
                continue
            seen.add(nxt)
            work.append(nxt)
    return seen


def prune_facts_only_src_sink(facts: Facts) -> Facts:
    """
    Keep only edges that can lie on a path from any SrcVar/SrcMem to any SinkVar/SinkMem.
    """
    adj: Dict[GraphNode, Set[GraphNode]] = {}
    radj: Dict[GraphNode, Set[GraphNode]] = {}

    def add_edge(a: GraphNode, b: GraphNode) -> None:
        adj.setdefault(a, set()).add(b)
        radj.setdefault(b, set()).add(a)

    for e in facts.v_edges:
        add_edge(_gn_v(e.a1, e.f1, e.v1), _gn_v(e.a2, e.f2, e.v2))
    for e in facts.m_edges:
        add_edge(_gn_m(e.a1, e.f1, e.m1), _gn_m(e.a2, e.f2, e.m2))
    for e in facts.v2m:
        add_edge(_gn_v(e.addr, e.func, e.var), _gn_m(e.addr, e.func, e.mem))
    for e in facts.m2v:
        add_edge(_gn_m(e.addr, e.func, e.mem), _gn_v(e.addr, e.func, e.var))

    src_nodes = set(_gn_v(s.addr, s.call_name, s.var) for s in facts.src_vars) | set(
        _gn_m(s.addr, s.call_name, s.mem) for s in facts.src_mems
    )
    sink_nodes = set(_gn_v(s.addr, s.call_name, s.var) for s in facts.sink_vars) | set(
        _gn_m(s.addr, s.call_name, s.mem) for s in facts.sink_mems
    )

    if not src_nodes or not sink_nodes:
        pruned = Facts()
        pruned.src_vars = list(facts.src_vars)
        pruned.sink_vars = list(facts.sink_vars)
        pruned.src_mems = list(facts.src_mems)
        pruned.sink_mems = list(facts.sink_mems)
        return pruned

    keep = (_bfs(src_nodes, adj) & _bfs(sink_nodes, radj)) | src_nodes | sink_nodes

    def kv(e) -> bool:
        return _gn_v(e.a1, e.f1, e.v1) in keep and _gn_v(e.a2, e.f2, e.v2) in keep

    def km(e) -> bool:
        return _gn_m(e.a1, e.f1, e.m1) in keep and _gn_m(e.a2, e.f2, e.m2) in keep

    def kv2m(e) -> bool:
        return _gn_v(e.addr, e.func, e.var) in keep and _gn_m(e.addr, e.func, e.mem) in keep

    def km2v(e) -> bool:
        return _gn_m(e.addr, e.func, e.mem) in keep and _gn_v(e.addr, e.func, e.var) in keep

    pruned = Facts()
    pruned.src_vars = list(facts.src_vars)
    pruned.sink_vars = list(facts.sink_vars)
    pruned.src_mems = list(facts.src_mems)
    pruned.sink_mems = list(facts.sink_mems)
    pruned.v_edges = [e for e in facts.v_edges if kv(e)]
    pruned.m_edges = [e for e in facts.m_edges if km(e)]
    pruned.v2m = [e for e in facts.v2m if kv2m(e)]
    pruned.m2v = [e for e in facts.m2v if km2v(e)]
    pruned.mem2rets = [
        e
        for e in facts.mem2rets
        if _gn_m(e.addr, e.call_name, e.mem) in keep
        and _gn_v(e.addr, e.call_name, e.var) in keep
    ]
    pruned.use_mems = [u for u in facts.use_mems if _gn_m(u.addr, u.func, u.name) in keep]
    return pruned


# ----------------------------
# Build FP: binary VEdge/MEdge/M2V/V2M/Mem2Ret; unary TaintVal/TaintMem
# ----------------------------

def build_fp() -> Tuple[Fixedpoint, Dict[str, object]]:
    fp = Fixedpoint()
    fp.set(engine="spacer")
    I = IntSort()

    UseMem = Function("UseMem", I, BoolSort())
    MemVersionId = Function("MemVersionId", I, I, I, BoolSort())

    SrcVar = Function("SrcVar", I, BoolSort())
    SinkVar = Function("SinkVar", I, BoolSort())
    SrcMem = Function("SrcMem", I, BoolSort())
    SinkMem = Function("SinkMem", I, BoolSort())

    VEdge = Function("VEdge", I, I, BoolSort())
    MEdge = Function("MEdge", I, I, BoolSort())
    M2V = Function("M2V", I, I, BoolSort())
    V2M = Function("V2M", I, I, BoolSort())
    Mem2Ret = Function("Mem2Ret", I, I, BoolSort())

    TaintVal = Function("TaintVal", I, BoolSort())
    TaintMem = Function("TaintMem", I, BoolSort())

    fp.register_relation(
        UseMem,
        MemVersionId,
        SrcVar,
        SinkVar,
        SrcMem,
        SinkMem,
        VEdge,
        MEdge,
        M2V,
        V2M,
        Mem2Ret,
        TaintVal,
        TaintMem,
    )

    m1, m2, f, x, v, v1, v2 = Ints("m1 m2 f x v v1 v2")
    fp.declare_var(m1, m2, f, x, v, v1, v2)

    # SSA mem carry: same (func_id, mem_ssa_id) at another use site
    fp.rule(
        TaintMem(m2),
        And(TaintMem(m1), MemVersionId(m1, f, x), MemVersionId(m2, f, x), UseMem(m2)),
    )

    fp.rule(TaintVal(v), SrcVar(v))
    fp.rule(TaintMem(m1), SrcMem(m1))

    fp.rule(TaintVal(v2), And(TaintVal(v1), VEdge(v1, v2)))
    fp.rule(TaintMem(m2), And(TaintVal(v1), V2M(v1, m2)))
    fp.rule(TaintMem(m2), And(TaintMem(m1), MEdge(m1, m2)))
    fp.rule(TaintVal(v2), And(TaintMem(m1), M2V(m1, v2)))

    # Tainted mem version (any site) + Mem2Ret sharing (func_id, mem_ssa_id)
    fp.rule(
        TaintVal(v),
        And(TaintMem(m1), Mem2Ret(m2, v), MemVersionId(m1, f, x), MemVersionId(m2, f, x)),
    )

    rel = {
        "UseMem": UseMem,
        "MemVersionId": MemVersionId,
        "SrcVar": SrcVar,
        "SinkVar": SinkVar,
        "SrcMem": SrcMem,
        "SinkMem": SinkMem,
        "VEdge": VEdge,
        "MEdge": MEdge,
        "M2V": M2V,
        "V2M": V2M,
        "Mem2Ret": Mem2Ret,
        "TaintVal": TaintVal,
        "TaintMem": TaintMem,
    }
    return fp, rel


def _fact_mem_version(fp: Fixedpoint, MemVersionId, addr: int, func: str, mem_key: str) -> None:
    fi, mi = _mem_version_ids(func, mem_key)
    fp.fact(MemVersionId(pack_m(addr, func, mem_key), fi, mi))


def load_facts(fp: Fixedpoint, rel: Dict[str, object], facts: Facts) -> None:
    UseMem = rel["UseMem"]
    MemVersionId = rel["MemVersionId"]
    SrcVar = rel["SrcVar"]
    SinkVar = rel["SinkVar"]
    SrcMem = rel["SrcMem"]
    SinkMem = rel["SinkMem"]
    VEdge = rel["VEdge"]
    MEdge = rel["MEdge"]
    M2V = rel["M2V"]
    V2M = rel["V2M"]
    Mem2Ret = rel["Mem2Ret"]

    for u in facts.use_mems:
        fp.fact(UseMem(pack_m(u.addr, u.func, u.name)))
        _fact_mem_version(fp, MemVersionId, u.addr, u.func, u.name)

    for s in facts.src_vars:
        fp.fact(SrcVar(pack_v(s.addr, s.call_name, s.var)))
    for s in facts.sink_vars:
        fp.fact(SinkVar(pack_v(s.addr, s.call_name, s.var)))

    for s in facts.src_mems:
        fp.fact(SrcMem(pack_m(s.addr, s.call_name, s.mem)))
        _fact_mem_version(fp, MemVersionId, s.addr, s.call_name, s.mem)
    for s in facts.sink_mems:
        fp.fact(SinkMem(pack_m(s.addr, s.call_name, s.mem)))
        _fact_mem_version(fp, MemVersionId, s.addr, s.call_name, s.mem)

    for e in facts.v_edges:
        fp.fact(VEdge(pack_v(e.a1, e.f1, e.v1), pack_v(e.a2, e.f2, e.v2)))

    for e in facts.m_edges:
        fp.fact(MEdge(pack_m(e.a1, e.f1, e.m1), pack_m(e.a2, e.f2, e.m2)))
        _fact_mem_version(fp, MemVersionId, e.a1, e.f1, e.m1)
        _fact_mem_version(fp, MemVersionId, e.a2, e.f2, e.m2)

    for e in facts.m2v:
        fp.fact(M2V(pack_m(e.addr, e.func, e.mem), pack_v(e.addr, e.func, e.var)))
        _fact_mem_version(fp, MemVersionId, e.addr, e.func, e.mem)

    for e in facts.v2m:
        fp.fact(V2M(pack_v(e.addr, e.func, e.var), pack_m(e.addr, e.func, e.mem)))
        _fact_mem_version(fp, MemVersionId, e.addr, e.func, e.mem)

    for e in facts.mem2rets:
        fp.fact(Mem2Ret(pack_m(e.addr, e.call_name, e.mem), pack_v(e.addr, e.call_name, e.var)))
        _fact_mem_version(fp, MemVersionId, e.addr, e.call_name, e.mem)


# ----------------------------
# Query helpers
# ----------------------------

def is_tainted_val(fp: Fixedpoint, rel: Dict[str, object], addr: int, func_name: str, var_key: str) -> bool:
    TaintVal = rel["TaintVal"]
    return fp.query(TaintVal(pack_v(addr, func_name, var_key))) == sat


def is_tainted_mem(fp: Fixedpoint, rel: Dict[str, object], addr: int, func_name: str, mem_key: str) -> bool:
    TaintMem = rel["TaintMem"]
    return fp.query(TaintMem(pack_m(addr, func_name, mem_key))) == sat


# ----------------------------
# Main entry
# ----------------------------

def solve(facts: Facts, *, only_src_sink: bool = False) -> List[Tuple[int, str, str]]:
    """
    Return sink hits as (addr, func_name, var_or_mem_key) for tainted sink_vars / sink_mems.
    """
    if only_src_sink:
        facts = prune_facts_only_src_sink(facts)

    _reset_node_packs()
    fp, rel = build_fp()
    load_facts(fp, rel, facts)

    hits: List[Tuple[int, str, str]] = []
    for sv in facts.sink_vars:
        if is_tainted_val(fp, rel, sv.addr, sv.call_name, sv.var):
            hits.append((sv.addr, sv.call_name, sv.var))
    for sm in facts.sink_mems:
        if is_tainted_mem(fp, rel, sm.addr, sm.call_name, sm.mem):
            hits.append((sm.addr, sm.call_name, sm.mem))
    return hits
