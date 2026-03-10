from __future__ import annotations

from typing import Dict, List, Tuple

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


# ----------------------------
# Main entry
# ----------------------------

def solve(facts: Facts) -> List[Tuple[int, str, str]]:
    """
    Returns list of alarm hits as tuples:
      (sink_addr, sink_func_name, sink_var_key)
    """
    fp, rel = build_fp()
    load_facts(fp, rel, facts)

    hits: List[Tuple[int, str, str]] = []
    for sv in facts.sink_vars:
        if is_tainted_val(fp, rel, sv.addr, sv.call_name, sv.var):
            hits.append((sv.addr, sv.call_name, sv.var))
    return hits