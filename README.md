# TaintMagician

TaintMagician is a taint analyzer built on **Binary Ninja MLIL**: it supports a **graph reachability** view of the same SSA facts (default) and an optional **Datalog** backend (**Z3** fixedpoint).

## Datalog rules

TaintMagician encodes an SSA def-use graph as Datalog relations (Z3 fixedpoint) and computes taint as the least fixed point. The same facts can also be read as a **directed graph** for a lighter **reachability-based** analysis (see below).

### Extracted facts (relations)

Facts are extracted from Binary Ninja **MLIL SSA** in `src/extractor.py` and loaded into the solver in `src/taint_solver.py`.
Each *value node* and *memory node* is uniquely identified by a tuple \((addr, function, ssa\_name)\) and then packed into a single ID for the Datalog engine.

- **`SrcVar(v)` / `SinkVar(v)`**: source/sink *value* nodes (SSA variables at a call site).
- **`SrcMem(m)` / `SinkMem(m)`**: source/sink *memory* nodes (SSA memory version at a call site).
- **`VEdge(v1, v2)`**: value-to-value def-use edges.
  - Created for local assignments (read → written) and for interprocedural parameter/return connections.
- **`MEdge(m1, m2)`**: memory-to-memory edges between SSA memory versions.
  - Created for memory version changes, `MEM_PHI`, calls, and returns (callee memory → caller memory).
- **`V2M(v, m)`**: value flows into memory (e.g., `STORE`).
- **`M2V(m, v)`**: memory flows into value (e.g., `LOAD` / aliased vars).
- **`UseMem(m)`**: marks memory nodes that are observed/used at some program point (used to limit “carry” propagation).
- **`MemVersionId(m, func_id, mem_ssa_id)`**: ties a packed memory node `m` to the underlying `(function, memory_version)` identity.
  - This is used to relate different packed nodes that represent the *same* SSA memory version within a function.
- **`Mem2Ret(m, v)`**: a helper relation used to model “return value depends on current memory”.
  - Emitted for `RET` and also for a small set of string helpers (e.g., `strchr`, `strstr`, …) so tainted memory can taint the returned pointer/value.

### Taint rules (core)

The solver computes two unary relations:

- **`TaintVal(v)`**: tainted SSA value node
- **`TaintMem(m)`**: tainted SSA memory node

Propagation rules:

```prolog
TaintVal(v) :- SrcVar(v).
TaintMem(m) :- SrcMem(m).

TaintVal(v2) :- TaintVal(v1), VEdge(v1, v2).
TaintMem(m2) :- TaintVal(v1), V2M(v1, m2).
TaintMem(m2) :- TaintMem(m1), MEdge(m1, m2).
TaintVal(v2) :- TaintMem(m1), M2V(m1, v2).
```

Memory “carry” for the *same* SSA memory version (within a function):

```prolog
TaintMem(m2) :-
  TaintMem(m1),
  MemVersionId(m1, f, x),
  MemVersionId(m2, f, x),
  UseMem(m2).
```

Memory-to-return modeling (tainted memory implies tainted return value when connected via `Mem2Ret` and the same `(function, mem_version)`):

```prolog
TaintVal(v) :-
  TaintMem(m1),
  Mem2Ret(m2, v),
  MemVersionId(m1, f, x),
  MemVersionId(m2, f, x).
```

Finally, an alarm is reported when a sink node is tainted:

- `SinkVar(v) ∧ TaintVal(v)`
- `SinkMem(m) ∧ TaintMem(m)`

### Reachability-based taint analysis

Besides the Z3 fixedpoint, the tool can treat **taint propagation as graph reachability**: each extracted fact type is mapped to **nodes** and **forward edges** in `src/facts_graph.py`. If taint can flow from a source node to a sink node along directed edges, the reachability pipeline reports an alarm (with optional per-sink pruning and a shortest path from each hit source to the sink).

**Logical nodes** (same identity as the solver’s packed nodes, but kept as readable tuples for pruning and paths):

| Kind | Form | Example |
|------|------|---------|
| **Value (V)** | `V(addr, func, var)` | `V(0x1000004ac, "_main", "x1#1@_main")` |
| **Memory (M)** | `M(addr, func, mem)` | `M(0x100000594, "_read_full", "mem#1@_read_full")` |

In the Datalog engine, `pack_v` / `pack_m` compress these tuples to integer IDs; the graph layer uses the tuple form for clarity.

**Facts → edges** (forward taint direction):

| Fact | Edge | Meaning |
|------|------|---------|
| `VEdge` | V → V | Value taint may propagate along the def-use link. |
| `MEdge` | M → M | Memory SSA / state may propagate between versions. |
| `V2M` | V → M | A value is stored into memory; taint may enter that mem node. |
| `M2V` | M → V | A value is loaded from memory; taint may leave the mem node. |
| `Mem2Ret` | M → V | A memory version is tied to a return/summary value. |

Optional **memory-version hubs** (`MV(func, mem_ssa)`) connect all M-sites that share the same SSA memory name within a function, approximating the `MemVersionId` join used in Datalog for pruning.

Run with **`--z3`** to use only the Datalog solver; **by default** (no `--vis` / `--z3`) the tool runs this reachability-based analysis.

## Usage

Running this tool requires **Binary Ninja Headless**.

```sh
pip install -r requirements.txt
# Graph reachability (default): prune per sink, list sources + shortest paths
./taint_magician /path/to/binary

./taint_magician /path/to/binary --z3    # Z3 fixedpoint + dump facts
./taint_magician /path/to/binary --vis    # visualization server (port 7777)
```

Run from the repo root with `PYTHONPATH` including `src`, or invoke `python3 src/main.py` the same way.

## Example

Target: `test/simple1.c`

```c
#include "example.h"

int main() {
  int x = 0;
  source(&x);
  sink(x); // bug
  return 0;
}
```

Output (reachability mode; exact SSA names depend on the binary):

```text
[ALARM] sink: _main @ 0x100000438  var=x0_1#2@_main
        src:  ...
        path: ... -> ... -> x0_1#2@_main
```

With **`--z3`**, alarms are single-line: `[ALARM] <func> @ 0x<addr>  var=<ssa_key>`.