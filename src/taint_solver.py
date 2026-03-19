from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

from z3 import And, BoolSort, Fixedpoint, IntSort, Function, Ints, sat

from constraint import Facts, func_ids, var_ids


# ----------------------------
# Helpers: ID mapping
# ----------------------------

def fid(func_name: str) -> int:
    return func_ids.get(func_name)

def vid(var_key: str) -> int:
    # var_key is expected to be stable & namespaced already (e.g., "x0#1@_start", "mem#2@_source")
    return var_ids.get(var_key)

Node = Tuple[str, int, str, str]  # (kind: "V"|"M", addr, func, name)

def _v(addr: int, func: str, var: str) -> Node:
    return ("V", addr, func, var)

def _m(addr: int, func: str, mem: str) -> Node:
    return ("M", addr, func, mem)

def _bfs(starts: Iterable[Node], adj: Dict[Node, Set[Node]]) -> Set[Node]:
    seen: Set[Node] = set()
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
    Prune facts to only those that can participate in a path:
      (any SrcVar/SrcMem) -> ... -> (any SinkVar/SinkMem)

    This is a pure, syntactic reachability filter over the *fact graph*,
    intended to reduce the number of edges/facts sent into Z3.
    """
    adj: Dict[Node, Set[Node]] = {}
    radj: Dict[Node, Set[Node]] = {}

    def add_edge(a: Node, b: Node) -> None:
        adj.setdefault(a, set()).add(b)
        radj.setdefault(b, set()).add(a)

    # Variable and memory edges
    for e in facts.v_edges:
        add_edge(_v(e.a1, e.f1, e.v1), _v(e.a2, e.f2, e.v2))
    for e in facts.m_edges:
        add_edge(_m(e.a1, e.f1, e.m1), _m(e.a2, e.f2, e.m2))

    # Cross edges at the same (addr, func)
    for e in facts.v2m:
        add_edge(_v(e.addr, e.func, e.var), _m(e.addr, e.func, e.mem))
    for e in facts.m2v:
        add_edge(_m(e.addr, e.func, e.mem), _v(e.addr, e.func, e.var))

    src_nodes: Set[Node] = set(_v(s.addr, s.call_name, s.var) for s in facts.src_vars) | set(
        _m(s.addr, s.call_name, s.mem) for s in facts.src_mems
    )
    sink_nodes: Set[Node] = set(_v(s.addr, s.call_name, s.var) for s in facts.sink_vars) | set(
        _m(s.addr, s.call_name, s.mem) for s in facts.sink_mems
    )

    # If there are no sources or no sinks, no edge can be on a src->sink path.
    if not src_nodes or not sink_nodes:
        pruned = Facts()
        pruned.src_vars = list(facts.src_vars)
        pruned.sink_vars = list(facts.sink_vars)
        pruned.src_mems = list(facts.src_mems)
        pruned.sink_mems = list(facts.sink_mems)
        return pruned

    fwd = _bfs(src_nodes, adj)
    bwd = _bfs(sink_nodes, radj)
    keep_nodes = (fwd & bwd) | src_nodes | sink_nodes

    def keep_vedge(e) -> bool:
        return _v(e.a1, e.f1, e.v1) in keep_nodes and _v(e.a2, e.f2, e.v2) in keep_nodes

    def keep_medge(e) -> bool:
        return _m(e.a1, e.f1, e.m1) in keep_nodes and _m(e.a2, e.f2, e.m2) in keep_nodes

    def keep_v2m(e) -> bool:
        return _v(e.addr, e.func, e.var) in keep_nodes and _m(e.addr, e.func, e.mem) in keep_nodes

    def keep_m2v(e) -> bool:
        return _m(e.addr, e.func, e.mem) in keep_nodes and _v(e.addr, e.func, e.var) in keep_nodes

    pruned = Facts()
    pruned.src_vars = list(facts.src_vars)
    pruned.sink_vars = list(facts.sink_vars)
    pruned.src_mems = list(facts.src_mems)
    pruned.sink_mems = list(facts.sink_mems)

    pruned.v_edges = [e for e in facts.v_edges if keep_vedge(e)]
    pruned.m_edges = [e for e in facts.m_edges if keep_medge(e)]
    pruned.v2m = [e for e in facts.v2m if keep_v2m(e)]
    pruned.m2v = [e for e in facts.m2v if keep_m2v(e)]

    # UseMem facts are only relevant if their (addr,func,mem) node survives.
    pruned.use_mems = [u for u in facts.use_mems if _m(u.addr, u.func, u.name) in keep_nodes]

    return pruned


# ----------------------------
# Build FP and register rules
# ----------------------------

def build_fp() -> Tuple[Fixedpoint, Dict[str, object]]:
    """
    Build fixedpoint with minimal, fast rules:
      - TaintVal / TaintMem recursion
      - VEdge, MEdge, M2V, V2M for propagation
      - SrcVar seeds, SinkVar queries
    """
    fp = Fixedpoint()
    fp.set(engine="spacer")

    I = IntSort()

    UseMem = Function("UseMem", I, I, I, BoolSort())  # (addr, func_id, mem_id)

    # Facts (provided by extractor/edge_builder)
    SrcVar  = Function("SrcVar",  I, I, I, BoolSort())                # (addr, func_id, var_id)
    SinkVar = Function("SinkVar", I, I, I, BoolSort())                # (addr, func_id, var_id)

    SrcMem  = Function("SrcMem",  I, I, I, BoolSort())    # (addr, func_id, mem_id)
    SinkMem = Function("SinkMem", I, I, I, BoolSort())    # (addr, func_id, mem_id)

    VEdge   = Function("VEdge", I, I, I, I, I, I, BoolSort())         # (a1,f1,v1,a2,f2,v2)
    MEdge   = Function("MEdge", I, I, I, I, I, I, BoolSort())         # (a1,f1,m1,a2,f2,m2)

    # Compressed cross edges (recommended)
    M2V     = Function("M2V", I, I, I, I, BoolSort())                 # (addr, func_id, mem_id, var_id)
    V2M     = Function("V2M", I, I, I, I, BoolSort())                 # (addr, func_id, var_id, mem_id)

    # Derived
    TaintVal = Function("TaintVal", I, I, I, BoolSort())
    TaintMem = Function("TaintMem", I, I, I, BoolSort())
    Alarm    = Function("Alarm", I, I, BoolSort())                    # (addr, func_id)

    fp.register_relation(UseMem, SrcVar, SinkVar, SrcMem, SinkMem, VEdge, \
        MEdge, M2V, V2M, TaintVal, TaintMem, Alarm)

    # Vars
    a1, f1, x1 = Ints("a1 f1 x1")
    a2, f2, x2 = Ints("a2 f2 x2")
    fp.declare_var(a1, f1, x1, a2, f2, x2)

    # ----------------------------
    # Rules
    # ----------------------------

    # Memory version carry: if a memory version is tainted, treat all its use sites as tainted too
    fp.rule(
        TaintMem(a2, f2, x2),
        And(TaintMem(a1, f1, x2),
            UseMem(a2, f1, x2),
            a1 >= 0)  # Optional: dummy condition; declare_var is usually enough to avoid spacer warnings about unused variables
    )

    # Seed: source variables taint
    fp.rule(TaintVal(a1, f1, x1), SrcVar(a1, f1, x1))

    fp.rule(TaintMem(a1, f1, x1), SrcMem(a1, f1, x1))

    # value -> value
    fp.rule(
        TaintVal(a2, f2, x2),
        And(TaintVal(a1, f1, x1),
            VEdge(a1, f1, x1, a2, f2, x2))
    )

    # value -> mem (store)
    fp.rule(
        TaintMem(a1, f1, x2),
        And(TaintVal(a1, f1, x1),
            V2M(a1, f1, x1, x2))
    )

    # mem -> mem (phi + retmem already compiled into MEdge)
    fp.rule(
        TaintMem(a2, f2, x2),
        And(TaintMem(a1, f1, x1),
            MEdge(a1, f1, x1, a2, f2, x2))
    )

    # mem -> value (load)
    fp.rule(
        TaintVal(a1, f1, x2),
        And(TaintMem(a1, f1, x1),
            M2V(a1, f1, x1, x2))
    )

    # Alarm (optional materialization; we mostly query TaintVal directly)
    fp.rule(
        Alarm(a1, f1),
        And(SinkVar(a1, f1, x1),
            TaintVal(a1, f1, x1))
    )

    rel = {
        "UseMem": UseMem,
        "SrcVar": SrcVar,
        "SinkVar": SinkVar,
        "SrcMem": SrcMem,
        "SinkMem": SinkMem,
        "VEdge": VEdge,
        "MEdge": MEdge,
        "M2V": M2V,
        "V2M": V2M,
        "TaintVal": TaintVal,
        "TaintMem": TaintMem,
        "Alarm": Alarm,
    }
    return fp, rel


# ----------------------------
# Load facts into FP
# ----------------------------

def load_facts(fp: Fixedpoint, rel: Dict[str, object], facts: Facts) -> None:
    UseMem = rel["UseMem"]
    SrcVar  = rel["SrcVar"]
    SinkVar = rel["SinkVar"]
    SrcMem  = rel["SrcMem"]
    SinkMem = rel["SinkMem"]
    VEdge   = rel["VEdge"]
    MEdge   = rel["MEdge"]
    M2V     = rel["M2V"]
    V2M     = rel["V2M"]

    for u in facts.use_mems:
        fp.fact(UseMem(u.addr, fid(u.func), vid(u.name)))
    
    # Seeds / sinks
    for s in facts.src_vars:
        fp.fact(SrcVar(s.addr, fid(s.call_name), vid(s.var)))

    for s in facts.sink_vars:
        fp.fact(SinkVar(s.addr, fid(s.call_name), vid(s.var)))

    for s in facts.src_mems:
        fp.fact(SrcMem(s.addr, fid(s.call_name), vid(s.mem)))

    for s in facts.sink_mems:
        fp.fact(SinkMem(s.addr, fid(s.call_name), vid(s.mem)))

    # Edges
    for e in facts.v_edges:
        fp.fact(VEdge(e.a1, fid(e.f1), vid(e.v1),
                      e.a2, fid(e.f2), vid(e.v2)))

    for e in facts.m_edges:
        fp.fact(MEdge(e.a1, fid(e.f1), vid(e.m1),
                      e.a2, fid(e.f2), vid(e.m2)))

    # Cross edges (compressed)
    for e in facts.m2v:
        fp.fact(M2V(e.addr, fid(e.func), vid(e.mem), vid(e.var)))

    for e in facts.v2m:
        fp.fact(V2M(e.addr, fid(e.func), vid(e.var), vid(e.mem)))


# ----------------------------
# Query helpers
# ----------------------------

def is_tainted_val(fp: Fixedpoint, rel: Dict[str, object], addr: int, func_name: str, var_key: str) -> bool:
    TaintVal = rel["TaintVal"]
    return fp.query(TaintVal(addr, fid(func_name), vid(var_key))) == sat


def solve(facts: Facts, *, only_src_sink: bool = False) -> List[Tuple[int, str, str]]:  # type: ignore[no-redef]
    """
    When `only_src_sink=True`, prune facts to only those that can lie on a
    source->sink path before feeding them into Z3.
    """
    if only_src_sink:
        facts = prune_facts_only_src_sink(facts)
    fp, rel = build_fp()
    load_facts(fp, rel, facts)

    hits: List[Tuple[int, str, str]] = []
    for sv in facts.sink_vars:
        if is_tainted_val(fp, rel, sv.addr, sv.call_name, sv.var):
            hits.append((sv.addr, sv.call_name, sv.var))
    return hits