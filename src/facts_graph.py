"""
Multi-layer taint graph from extracted facts.

Nodes (logical SSA, tuple form — distinct from Z3 pack_v/pack_m integers):
  - V-node: ("V", addr, func, var)
  - M-node: ("M", addr, func, mem)
  - MV-node (optional hub): ("MV", func, mem_ssa)  — SSA memory version key

Edges follow forward taint flow (same direction as the Z3 fixedpoint rules):
  VEdge / MEdge / V2M / M2V / Mem2Ret, plus M <-> MV hubs when enabled.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    DefaultDict,
    Deque,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

from constraint import (
    Facts,
    MEdge,
    SinkMemFact,
    SinkVarFact,
    SrcMemFact,
    SrcVarFact,
    VEdge,
)

# -----------------------------------------------------------------------------
# Node types
# -----------------------------------------------------------------------------

VNode = Tuple[Literal["V"], int, str, str]
MNode = Tuple[Literal["M"], int, str, str]
MVNode = Tuple[Literal["MV"], str, str]
GraphNode = Union[VNode, MNode, MVNode]


def make_v(addr: int, func: str, var: str) -> VNode:
    return ("V", addr, func, var)


def make_m(addr: int, func: str, mem: str) -> MNode:
    return ("M", addr, func, mem)


def make_mv(func: str, mem_ssa: str) -> MVNode:
    return ("MV", func, mem_ssa)


# -----------------------------------------------------------------------------
# Graph container & construction
# -----------------------------------------------------------------------------


@dataclass
class FactsGraph:
    """Forward adjacency (taint propagation direction)."""

    nodes: Set[GraphNode] = field(default_factory=set)
    adj: DefaultDict[GraphNode, Set[GraphNode]] = field(
        default_factory=lambda: defaultdict(set)
    )

    def add_edge(self, src: GraphNode, dst: GraphNode) -> None:
        self.nodes.add(src)
        self.nodes.add(dst)
        self.adj[src].add(dst)

    def reverse_adj(self) -> DefaultDict[GraphNode, Set[GraphNode]]:
        rev: DefaultDict[GraphNode, Set[GraphNode]] = defaultdict(set)
        for u, outs in self.adj.items():
            for v in outs:
                rev[v].add(u)
        return rev


def build_facts_graph(facts: Facts, *, include_mv_hubs: bool = True) -> FactsGraph:
    """
    Build the fact-derived multi-layer graph.

    If include_mv_hubs is True, for each (func, mem_ssa) that appears on any M-node,
    add MV(func, mem_ssa) and edges M(...) -> MV -> M(...) for all M-sites with that key
    (approximates MemVersionId sharing for pruning).
    """
    g = FactsGraph()

    for e in facts.v_edges:
        g.add_edge(make_v(e.a1, e.f1, e.v1), make_v(e.a2, e.f2, e.v2))

    for e in facts.m_edges:
        g.add_edge(make_m(e.a1, e.f1, e.m1), make_m(e.a2, e.f2, e.m2))

    for e in facts.v2m:
        g.add_edge(make_v(e.addr, e.func, e.var), make_m(e.addr, e.func, e.mem))

    for e in facts.m2v:
        g.add_edge(make_m(e.addr, e.func, e.mem), make_v(e.addr, e.func, e.var))

    for e in facts.mem2rets:
        g.add_edge(make_m(e.addr, e.call_name, e.mem), make_v(e.addr, e.call_name, e.var))

    for u in facts.use_mems:
        g.nodes.add(make_m(u.addr, u.func, u.name))
    for s in facts.src_vars:
        g.nodes.add(make_v(s.addr, s.call_name, s.var))
    for s in facts.sink_vars:
        g.nodes.add(make_v(s.addr, s.call_name, s.var))
    for s in facts.src_mems:
        g.nodes.add(make_m(s.addr, s.call_name, s.mem))
    for s in facts.sink_mems:
        g.nodes.add(make_m(s.addr, s.call_name, s.mem))

    if include_mv_hubs:
        m_by_version: Dict[Tuple[str, str], List[MNode]] = defaultdict(list)
        for n in g.nodes:
            if n[0] != "M":
                continue
            mn = cast(MNode, n)
            m_by_version[(mn[2], mn[3])].append(mn)

        for (func, mem), sites in m_by_version.items():
            if len(sites) < 2:
                continue
            hub = make_mv(func, mem)
            for mn in sites:
                g.add_edge(mn, hub)
                g.add_edge(hub, mn)

    return g


# -----------------------------------------------------------------------------
# Pure graph algorithms (no Facts)
# -----------------------------------------------------------------------------


def nodes_reachable(
    starts: Set[GraphNode], adj: DefaultDict[GraphNode, Set[GraphNode]]
) -> Set[GraphNode]:
    seen: Set[GraphNode] = set(starts)
    work = list(starts)
    i = 0
    while i < len(work):
        u = work[i]
        i += 1
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                work.append(v)
    return seen


def shortest_path_bfs(
    adj: DefaultDict[GraphNode, Set[GraphNode]],
    start: GraphNode,
    goal: GraphNode,
) -> Optional[List[GraphNode]]:
    """Unweighted shortest path on forward adjacency."""
    if start == goal:
        return [start]
    parent: Dict[GraphNode, GraphNode] = {}
    seen: Set[GraphNode] = {start}
    dq: Deque[GraphNode] = deque([start])
    while dq:
        u = dq.popleft()
        for v in adj[u]:
            if v in seen:
                continue
            seen.add(v)
            parent[v] = u
            if v == goal:
                out: List[GraphNode] = [goal]
                cur = goal
                while cur != start:
                    cur = parent[cur]
                    out.append(cur)
                out.reverse()
                return out
            dq.append(v)
    return None


# -----------------------------------------------------------------------------
# Facts ↔ graph nodes
# -----------------------------------------------------------------------------


def source_nodes(facts: Facts) -> Set[GraphNode]:
    s: Set[GraphNode] = set()
    for x in facts.src_vars:
        s.add(make_v(x.addr, x.call_name, x.var))
    for x in facts.src_mems:
        s.add(make_m(x.addr, x.call_name, x.mem))
    return s


def sink_start_nodes(small: Facts) -> Set[GraphNode]:
    s: Set[GraphNode] = set()
    for sv in small.sink_vars:
        s.add(make_v(sv.addr, sv.call_name, sv.var))
    for sm in small.sink_mems:
        s.add(make_m(sm.addr, sm.call_name, sm.mem))
    return s


def keep_set_for_sink(
    graph: FactsGraph, facts: Facts, sink: GraphNode
) -> Set[GraphNode]:
    """FWD(sources) ∩ BWD(sink) on ``graph``."""
    fwd = nodes_reachable(source_nodes(facts), graph.adj)
    bwd = nodes_reachable({sink}, graph.reverse_adj())
    return fwd & bwd


def filter_facts_to_keep(
    facts: Facts,
    keep: Set[GraphNode],
    *,
    sink_var: Optional[SinkVarFact],
    sink_mem: Optional[SinkMemFact],
    sink_node: GraphNode,
) -> Facts:
    """Copy only facts whose endpoints lie in ``keep``; retain at most one sink."""
    out = Facts()

    for e in facts.v_edges:
        u, v = make_v(e.a1, e.f1, e.v1), make_v(e.a2, e.f2, e.v2)
        if u in keep and v in keep:
            out.v_edges.append(e)

    for e in facts.m_edges:
        u, v = make_m(e.a1, e.f1, e.m1), make_m(e.a2, e.f2, e.m2)
        if u in keep and v in keep:
            out.m_edges.append(e)

    for e in facts.v2m:
        u, v = make_v(e.addr, e.func, e.var), make_m(e.addr, e.func, e.mem)
        if u in keep and v in keep:
            out.v2m.append(e)

    for e in facts.m2v:
        u, v = make_m(e.addr, e.func, e.mem), make_v(e.addr, e.func, e.var)
        if u in keep and v in keep:
            out.m2v.append(e)

    for e in facts.mem2rets:
        u, v = make_m(e.addr, e.call_name, e.mem), make_v(e.addr, e.call_name, e.var)
        if u in keep and v in keep:
            out.mem2rets.append(e)

    for u in facts.use_mems:
        if make_m(u.addr, u.func, u.name) in keep:
            out.use_mems.append(u)

    for x in facts.src_vars:
        if make_v(x.addr, x.call_name, x.var) in keep:
            out.src_vars.append(x)

    for x in facts.src_mems:
        if make_m(x.addr, x.call_name, x.mem) in keep:
            out.src_mems.append(x)

    if sink_var is not None and sink_node in keep:
        out.sink_vars.append(sink_var)
    if sink_mem is not None and sink_node in keep:
        out.sink_mems.append(sink_mem)

    for d in facts.defs:
        if make_v(d.addr, d.func, d.name) in keep:
            out.defs.append(d)

    for u in facts.uses:
        if make_v(u.addr, u.func, u.name) in keep:
            out.uses.append(u)

    for d in facts.def_mems:
        if make_m(d.addr, d.func, d.name) in keep:
            out.def_mems.append(d)

    kept_src_keys = {(x.addr, x.call_name) for x in out.src_vars} | {
        (x.addr, x.call_name) for x in out.src_mems
    }
    out.srcs = [s for s in facts.srcs if (s.addr, s.call_name) in kept_src_keys]

    kept_sink_keys = {(x.addr, x.call_name) for x in out.sink_vars} | {
        (x.addr, x.call_name) for x in out.sink_mems
    }
    out.sinks = [s for s in facts.sinks if (s.addr, s.call_name) in kept_sink_keys]

    return out


# -----------------------------------------------------------------------------
# Pruning & reachability results
# -----------------------------------------------------------------------------


def prune_for_sink(
    facts: Facts,
    graph: FactsGraph,
    *,
    sink_var: Optional[SinkVarFact] = None,
    sink_mem: Optional[SinkMemFact] = None,
) -> Facts:
    """
    Intersect forward reachability from all src_var / src_mem nodes with backward
    reachability from a single sink.  ``graph`` must come from ``build_facts_graph``
    on the same ``facts`` (matching ``include_mv_hubs``).
    """
    if (sink_var is None) == (sink_mem is None):
        raise ValueError("exactly one of sink_var and sink_mem must be provided")

    if sink_var is not None:
        sink_node: GraphNode = make_v(sink_var.addr, sink_var.call_name, sink_var.var)
    else:
        assert sink_mem is not None
        sink_node = make_m(sink_mem.addr, sink_mem.call_name, sink_mem.mem)

    keep = keep_set_for_sink(graph, facts, sink_node)
    return filter_facts_to_keep(
        facts, keep, sink_var=sink_var, sink_mem=sink_mem, sink_node=sink_node
    )


@dataclass(frozen=True)
class SinkSourceReachability:
    """
    ``facts`` sources that lie in the backward closure from ``small``'s sinks
    on the graph built from ``small``.
    """

    reachable_src_vars: Tuple[SrcVarFact, ...]
    reachable_src_mems: Tuple[SrcMemFact, ...]

    @property
    def alarm(self) -> bool:
        return bool(self.reachable_src_vars or self.reachable_src_mems)

    def __bool__(self) -> bool:
        return self.alarm


def upstream_nodes(graph: FactsGraph, starts: Set[GraphNode]) -> Set[GraphNode]:
    """All nodes reachable from ``starts`` along **reverse** (backward taint) edges."""
    return nodes_reachable(starts, graph.reverse_adj())


def sources_hitting_nodes(facts: Facts, nodes: Set[GraphNode]) -> SinkSourceReachability:
    """Which ``facts`` src_var / src_mem graph nodes appear in ``nodes``."""
    hit_v = tuple(
        sv for sv in facts.src_vars if make_v(sv.addr, sv.call_name, sv.var) in nodes
    )
    hit_m = tuple(
        sm for sm in facts.src_mems if make_m(sm.addr, sm.call_name, sm.mem) in nodes
    )
    return SinkSourceReachability(hit_v, hit_m)


def compute_reachable(
    facts: Facts,
    small: Facts,
    *,
    include_mv_hubs: bool = True,
) -> SinkSourceReachability:
    starts = sink_start_nodes(small)
    if not starts:
        return SinkSourceReachability((), ())
    g = build_facts_graph(small, include_mv_hubs=include_mv_hubs)
    up = upstream_nodes(g, starts)
    return sources_hitting_nodes(facts, up)


# -----------------------------------------------------------------------------
# Path formatting
# -----------------------------------------------------------------------------


def format_graph_node(n: GraphNode) -> str:
    k = n[0]
    if k == "V":
        return cast(VNode, n)[3]
    if k == "M":
        return cast(MNode, n)[3]
    if k == "MV":
        _, func, mem_ssa = cast(MVNode, n)
        return f"⟨MV⟩{mem_ssa}@{func}"
    return str(n)


def format_taint_path(path: List[GraphNode]) -> str:
    return " -> ".join(format_graph_node(n) for n in path)


def shortest_forward_path(
    small: Facts,
    start: GraphNode,
    goal: GraphNode,
    *,
    include_mv_hubs: bool = True,
    graph: Optional[FactsGraph] = None,
) -> Optional[List[GraphNode]]:
    g = graph or build_facts_graph(small, include_mv_hubs=include_mv_hubs)
    return shortest_path_bfs(g.adj, start, goal)


# -----------------------------------------------------------------------------
# Reporting (stdout)
# -----------------------------------------------------------------------------


def format_src_var_line(sv: SrcVarFact) -> str:
    return f"{sv.call_name} @ 0x{sv.addr:x}  var={sv.var}"


def format_src_mem_line(sm: SrcMemFact) -> str:
    return f"{sm.call_name} @ 0x{sm.addr:x}  mem={sm.mem}"


def iter_reachable_source_rows(
    reach: SinkSourceReachability,
) -> Iterable[Tuple[GraphNode, str]]:
    for sv in reach.reachable_src_vars:
        yield make_v(sv.addr, sv.call_name, sv.var), format_src_var_line(sv)
    for sm in reach.reachable_src_mems:
        yield make_m(sm.addr, sm.call_name, sm.mem), format_src_mem_line(sm)


def print_sink_reachability_alarm(
    sink_line: str,
    reach: SinkSourceReachability,
    subgraph: FactsGraph,
    sink_node: GraphNode,
) -> None:
    print(f"[ALARM] sink: {sink_line}")
    for start, src_line in iter_reachable_source_rows(reach):
        print(f"        src:  {src_line}")
        path = shortest_path_bfs(subgraph.adj, start, sink_node)
        if path is None:
            print("        path: (unresolved)")
        else:
            print(f"        path: {format_taint_path(path)}")


def _iter_var_sink_jobs(
    facts: Facts, graph: FactsGraph
) -> Iterable[Tuple[Facts, str, GraphNode]]:
    for sv in facts.sink_vars:
        sub = prune_for_sink(facts, graph, sink_var=sv)
        line = f"{sv.call_name} @ 0x{sv.addr:x}  var={sv.var}"
        yield sub, line, make_v(sv.addr, sv.call_name, sv.var)


def _iter_mem_sink_jobs(
    facts: Facts, graph: FactsGraph
) -> Iterable[Tuple[Facts, str, GraphNode]]:
    for sm in facts.sink_mems:
        sub = prune_for_sink(facts, graph, sink_mem=sm)
        line = f"{sm.call_name} @ 0x{sm.addr:x}  mem={sm.mem}"
        yield sub, line, make_m(sm.addr, sm.call_name, sm.mem)


def _print_reachability_section(
    header: str,
    footer: str,
    jobs: Iterable[Tuple[Facts, str, GraphNode]],
    facts: Facts,
    *,
    include_mv_hubs: bool,
) -> None:
    print(header)
    for sub_facts, sink_line, sink_node in jobs:
        reach = compute_reachable(facts, sub_facts, include_mv_hubs=include_mv_hubs)
        if not reach:
            continue
        sub_g = build_facts_graph(sub_facts, include_mv_hubs=include_mv_hubs)
        print_sink_reachability_alarm(sink_line, reach, sub_g, sink_node)
    print(footer)


def report_reachability_alarms(
    facts: Facts,
    graph: FactsGraph,
    *,
    include_mv_hubs: bool = True,
) -> None:
    _print_reachability_section(
        "====== sink vars ======",
        "====== end sink vars ======\n",
        _iter_var_sink_jobs(facts, graph),
        facts,
        include_mv_hubs=include_mv_hubs,
    )
    _print_reachability_section(
        "====== sink mems ======",
        "====== end sink mems ======\n",
        _iter_mem_sink_jobs(facts, graph),
        facts,
        include_mv_hubs=include_mv_hubs,
    )
