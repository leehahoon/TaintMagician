from __future__ import annotations

from dataclasses import dataclass, field


# ----------------------------
# Mappers (global management: func_ids, var_ids)
# ----------------------------

class IdMapper:
    """
    Bidirectional mapping between strings and integer IDs. 
    Used purely as a data type.
    """
    def __init__(self, start: int = 1):
        self._next = start
        self._to_id: dict[str, int] = {}
        self._to_str: dict[int, str] = {}

    def get(self, s: str) -> int:
        if s in self._to_id:
            return self._to_id[s]
        i = self._next
        self._next += 1
        self._to_id[s] = i
        self._to_str[i] = s
        return i

    def rev(self, i: int) -> str:
        return self._to_str.get(i, f"<unknown:{i}>")


# Global mappers: manage function/variable names as integer IDs
func_ids: IdMapper = IdMapper()
var_ids: IdMapper = IdMapper()


# ----------------------------
# Fact data types 
# ----------------------------

@dataclass(frozen=True)
class DefFact:
    addr: int
    func: str
    name: str

    def __str__(self) -> str:
        return f"def(0x{self.addr:x}, {self.func}, {self.name})"


@dataclass(frozen=True)
class UseFact:
    addr: int
    func: str
    name: str

    def __str__(self) -> str:
        return f"use(0x{self.addr:x}, {self.func}, {self.name})"


@dataclass(frozen=True)
class DefMemFact:
    addr: int
    func: str
    name: str

    def __str__(self) -> str:
        return f"def_mem(0x{self.addr:x}, {self.func}, {self.name})"


@dataclass(frozen=True)
class UseMemFact:
    addr: int
    func: str
    name: str

    def __str__(self) -> str:
        return f"use_mem(0x{self.addr:x}, {self.func}, {self.name})"


@dataclass(frozen=True)
class SrcFact:
    addr: int
    call_name: str

    def __str__(self) -> str:
        return f"src(0x{self.addr:x}, {self.call_name})"


@dataclass(frozen=True)
class SinkFact:
    addr: int
    call_name: str

    def __str__(self) -> str:
        return f"sink(0x{self.addr:x}, {self.call_name})"

@dataclass(frozen=True)
class SrcVarFact:
    addr: int
    call_name: str
    var: str

    def __str__(self) -> str:
        return f"src_var(0x{self.addr:x}, {self.call_name}, {self.var})"

@dataclass(frozen=True)
class SinkVarFact:
    addr: int
    call_name: str
    var: str

    def __str__(self) -> str:
        return f"sink_var(0x{self.addr:x}, {self.call_name}, {self.var})"

@dataclass(frozen=True)
class SrcMemFact:
    addr: int
    call_name: str
    mem: str

    def __str__(self) -> str:
        return f"src_mem(0x{self.addr:x}, {self.call_name}, {self.mem})"

@dataclass(frozen=True)
class SinkMemFact:
    addr: int
    call_name: str
    mem: str

    def __str__(self) -> str:
        return f"sink_mem(0x{self.addr:x}, {self.call_name}, {self.mem})"

# ----------------------------
# Edge data types (def-use edges)
# ----------------------------

@dataclass(frozen=True)
class VEdge:
    """Edge between variable def and use. (def-side addr, func, var) → (use-side addr, func, var)"""
    a1: int
    f1: str
    v1: str
    a2: int
    f2: str
    v2: str

    def __str__(self) -> str:
        return f"VEdge(0x{self.a1:x},{self.f1},{self.v1} -> 0x{self.a2:x},{self.f2},{self.v2})"


@dataclass(frozen=True)
class MEdge:
    """Edge between memory def and use. (def-side addr, func, mem) → (use-side addr, func, mem)"""
    a1: int
    f1: str
    m1: str
    a2: int
    f2: str
    m2: str

    def __str__(self) -> str:
        return f"MEdge(0x{self.a1:x},{self.f1},{self.m1} -> 0x{self.a2:x},{self.f2},{self.m2})"


@dataclass(frozen=True)
class M2V:
    addr: int
    func: str
    mem: str
    var: str

    def __str__(self) -> str:
        return f"M2V(0x{self.addr:x},{self.func},{self.mem} -> {self.var})"

@dataclass(frozen=True)
class V2M:
    addr: int
    func: str
    var: str
    mem: str

    def __str__(self) -> str:
        return f"V2M(0x{self.addr:x},{self.func},{self.var} -> {self.mem})"

@dataclass
class Facts:
    """Container for extracted facts and edges.

    - extractor: fills defs/uses/mem/src/sink/m2v/v2m, etc.
    - edge_builder: fills v_edges/m_edges, etc.
    """
    defs: list[DefFact] = field(default_factory=list)
    uses: list[UseFact] = field(default_factory=list)
    def_mems: list[DefMemFact] = field(default_factory=list)
    use_mems: list[UseMemFact] = field(default_factory=list)
    srcs: list[SrcFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    src_vars: list[SrcVarFact] = field(default_factory=list)
    sink_vars: list[SinkVarFact] = field(default_factory=list)
    src_mems: list[SrcMemFact] = field(default_factory=list)
    sink_mems: list[SinkMemFact] = field(default_factory=list)
    v_edges: list[VEdge] = field(default_factory=list)
    m_edges: list[MEdge] = field(default_factory=list)
    m2v: list[M2V] = field(default_factory=list)
    v2m: list[V2M] = field(default_factory=list)

def dump_facts(facts: Facts) -> None:
    """Print `Facts` contents to stdout, grouped by section."""
    def print_section(title: str, items: list) -> None:
        print(f"\n=== {title} ({len(items)}) ===")
        for x in items:
            print(f"  {x}")

    print_section("Defs", facts.defs)
    print_section("Uses", facts.uses)
    print_section("DefMem", facts.def_mems)
    print_section("UseMem", facts.use_mems)
    print_section("Sources", facts.srcs)
    print_section("Sinks", facts.sinks)
    print_section("VEdges", facts.v_edges)
    print_section("MEdges", facts.m_edges)
    print_section("M2V", facts.m2v)
    print_section("V2M", facts.v2m)
    print_section("SrcVar", facts.src_vars)
    print_section("SinkVar", facts.sink_vars)
    print_section("SrcMem", facts.src_mems)
    print_section("SinkMem", facts.sink_mems)

