# TaintMagician

TaintMagician is a **Datalog-based taint analyzer** built on **Binary Ninja MLIL**, enabling taint analysis on **binary programs**.

## Datalog rules

TaintMagician encodes an SSA def-use graph as Datalog relations (Z3 fixedpoint) and computes taint as the least fixed point.

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

## Usage

Running this tool requires **Binary Ninja Headless**.

```sh
pip install -r requirements.txt
./taint_magician [program]
```

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

Output:

```sh
./taint_magician test/simple1
...
[ALARM] _main @ 0x100000438  var=x0_1#2@_main ; variable taint
[ALARM] _main @ 0x100000438  var=mem#3@_main  ; memory taint
```