from __future__ import annotations

from collections import defaultdict

from constraint import Facts, VEdge, MEdge


def build_edges(facts: Facts) -> None:
    """
    Connect Def-Use and populate variable edges (VEdge) 
    and memory edges (MEdge) in facts.
    """
    # facts.v_edges.clear()
    # facts.m_edges.clear()
    build_var_edges(facts)
    # build_mem_edges(facts)


def _group_by_name(items, name_attr: str = "name"):
    """
    Group items into a dictionary of (name -> [item, ...]). 
    Used when matching only by the same name.
    """
    out = defaultdict(list)
    for x in items:
        out[getattr(x, name_attr)].append(x)
    return out


def build_var_edges(facts: Facts) -> None:
    """
    Connect Def and Use with the same variable name to create VEdges. 
    Uses name-based indexing in O(D+U+E).
    """
    defs_by_name = _group_by_name(facts.defs)
    uses_by_name = _group_by_name(facts.uses)
    for name, def_list in defs_by_name.items():
        for u in uses_by_name.get(name, ()):
            for d in def_list:
                facts.v_edges.append(
                    VEdge(a1=d.addr, f1=d.func, v1=d.name, a2=u.addr, f2=u.func, v2=u.name)
                )


def build_mem_edges(facts: Facts) -> None:
    """
    Connect DefMem and UseMem with the same memory name to create MEdges.
    Uses name-based indexing in O(D+U+E).
    """
    defs_by_name = _group_by_name(facts.def_mems)
    uses_by_name = _group_by_name(facts.use_mems)
    for name, def_list in defs_by_name.items():
        for u in uses_by_name.get(name, ()):
            for d in def_list:
                facts.m_edges.append(
                    MEdge(a1=d.addr, f1=d.func, m1=d.name, a2=u.addr, f2=u.func, m2=u.name)
                )
