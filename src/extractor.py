from __future__ import annotations

from typing import Any, Iterator, NamedTuple

import binaryninja
from binaryninja import BinaryView


class CallContext(NamedTuple):
    """Context for a single call (address, function name, target)."""
    caller_addr: int
    caller_func_name: str
    callee_func_name: str
    target_func: Any


class ReturnSiteContext(NamedTuple):
    """A single return-site connection: caller/callee pair."""
    caller_func: Any
    caller_instr: Any
    callee_func: Any
    callee_instr: Any

from constraint import (
    Facts,
    DefFact,
    UseFact,
    DefMemFact,
    UseMemFact,
    SrcFact,
    SinkFact,
    SrcVarFact,
    SinkVarFact,
    SrcMemFact,
    SinkMemFact,
    VEdge,
    MEdge,
    M2V,
    V2M,
    func_ids,
    var_ids,
)

# Keywords for detecting source/sink (module-level constants)
# ["keyword", param_index]
# Ex) read(fd, buf, len) -> param_index=1 when taint `buf`
_SRC_KEYWORDS = (["source", 0], ["read", 1], ["recv", 1])
_SINK_KEYWORDS = (["sink", 0], ["strcpy", 1], ["sprintf", 1])


# ---------------------------------------------------------------------------
# Main Entry: extract facts from a binary
# ---------------------------------------------------------------------------

def extract(bv: BinaryView, facts: Facts | None = None) -> Facts:
    if facts is None:
        facts = Facts()
    for func in bv.functions:
        mlil = func.mlil
        if mlil is None:
            continue
        for block in mlil.ssa_form.basic_blocks:
            for instr in block:
                handle_instr(bv, func, instr, facts)
    return facts


def handle_instr(bv: BinaryView, func: Any, instr: Any, facts: Facts) -> None:
    """Dispatch def/use/memory/call/return collection for a single MLIL instruction."""
    ssa = instr.ssa_form
    if ssa is None:
        return

    collect_def_vars(ssa, func, facts)
    collect_use_vars(ssa, func, facts)
    collect_assign_vars(ssa, func, facts)

    op = ssa.operation.name
    if op == "MLIL_SET_VAR_SSA":
        collect_m2v_ssa(ssa, func, facts)
        collect_mem(ssa, func, facts)
    elif op == "MLIL_VAR_PHI":
        handle_var_phi(ssa, func, facts)
    elif op == "MLIL_MEM_PHI":
        collect_mem_phi(ssa, func, facts)
    elif op == "MLIL_LOAD_SSA":
        collect_m2v_ssa(ssa, func, facts)
    elif op == "MLIL_STORE_SSA":
        collect_v2m_ssa(ssa, func, facts)
    elif op == "MLIL_CALL_SSA":
        handle_call(func, ssa, facts)
    elif op == "MLIL_RET":
        handle_return(bv, func, ssa, facts)


# ---------------------------------------------------------------------------
# Name/memory-version strings (single responsibility: variable/memory name generation)
# ---------------------------------------------------------------------------

def var_base_name_mlil_ssa(var: Any) -> str:
    """MediumLevelILVarSsa: str(var) is already in the form 'x0#1'."""
    return str(var)


def var_base_name_ssa(var: Any) -> str:
    """SSAVariable: var.var + version."""
    v = var.var
    ver = var.version
    name = getattr(v, "name", None) or str(v)
    return f"{name}#{ver}"


def var_base_name_variable(var: Any) -> str:
    """BN Variable (non-SSA): no version."""
    return getattr(var, "name", None) or str(var)


def var_base_name(var: Any) -> str:
    """Return a variable object as a basic string in the form 'name' or 'name#version'."""
    if isinstance(var, binaryninja.mediumlevelil.MediumLevelILVarSsa):
        return var_base_name_mlil_ssa(var)
    if isinstance(var, binaryninja.mediumlevelil.SSAVariable):
        return var_base_name_ssa(var)
    if isinstance(var, binaryninja.variable.Variable):
        return var_base_name_variable(var)
    if isinstance(var, int):
        return f"const:{var}"
    if hasattr(var, "version"):
        return str(var)
    return str(var)


def naming_var(var: Any, func_name: str) -> str:
    """Return the normalized variable name, e.g. 'x0#1@_start'."""
    return var_base_name(var) + "@" + func_name


def naming_mem(version: int, func_name: str) -> str:
    """Return the normalized memory version name, e.g. 'mem#1@_start'."""
    return "mem#" + str(version) + "@" + func_name


# ---------------------------------------------------------------------------
# Mapper registration (register names only into func_ids and var_ids)
# ---------------------------------------------------------------------------

def ensure_registered(func_name: str, *var_names: str) -> None:
    func_ids.get(func_name)
    for name in var_names:
        var_ids.get(name)


# ---------------------------------------------------------------------------
# Def / Use variables
# ---------------------------------------------------------------------------

def add_def_var(instr: Any, func: Any, var: Any, facts: Facts) -> None:
    """Add exactly one Def fact for a single variable."""
    func_name = func.name
    name = naming_var(var, func_name)
    ensure_registered(func_name, name)
    facts.defs.append(DefFact(addr=instr.address, func=func_name, name=name))


def collect_def_vars(instr: Any, func: Any, facts: Facts) -> None:
    """Add Def facts for all vars_written in the instruction."""
    for var in instr.vars_written or ():
        add_def_var(instr, func, var, facts)


def add_use_var(instr: Any, func: Any, var: Any, facts: Facts) -> None:
    """Add exactly one Use fact for a single variable."""
    func_name = func.name
    name = naming_var(var, func_name)
    ensure_registered(func_name, name)
    facts.uses.append(UseFact(addr=instr.address, func=func_name, name=name))


def collect_use_vars(instr: Any, func: Any, facts: Facts) -> None:
    """Add Use facts for all vars_read in the instruction."""
    for var in instr.vars_read or ():
        add_use_var(instr, func, var, facts)


def handle_var_phi(ssa: Any, func: Any, facts: Facts) -> None:
    collect_def_vars(ssa, func, facts)
    collect_use_vars(ssa, func, facts)


def collect_assign_vars(ssa: Any, func: Any, facts: Facts) -> None:
    for written_var in ssa.vars_written:
        for read_var in ssa.vars_read:
            written_name = naming_var(written_var, func.name)
            read_name = naming_var(read_var, func.name)
            ensure_registered(func.name, written_name)
            ensure_registered(func.name, read_name)
            facts.v_edges.append(
                VEdge(
                    a1=ssa.address,
                    f1=func.name,
                    v1=read_name,
                    a2=ssa.address,
                    f2=func.name,
                    v2=written_name,
                )
            )


# ---------------------------------------------------------------------------
# Memory Def/Use
# ---------------------------------------------------------------------------

def add_def_mem(addr: int, func_name: str, mem_name: str, facts: Facts) -> None:
    ensure_registered(func_name, mem_name)
    facts.def_mems.append(DefMemFact(addr=addr, func=func_name, name=mem_name))


def add_use_mem(addr: int, func_name: str, mem_name: str, facts: Facts) -> None:
    ensure_registered(func_name, mem_name)
    facts.use_mems.append(UseMemFact(addr=addr, func=func_name, name=mem_name))


def collect_mem_version_change(instr: Any, func: Any, facts: Facts) -> None:
    """When the memory version changes: add exactly one def_mem and one use_mem."""
    addr = instr.address
    func_name = func.name
    def_name = naming_mem(instr.ssa_memory_version_after, func_name)
    use_name = naming_mem(instr.ssa_memory_version, func_name)
    add_def_mem(addr, func_name, def_name, facts)
    add_use_mem(addr, func_name, use_name, facts)


def is_var_aliased(instr: Any) -> bool:
    """Return True if the instruction's src is MLIL_VAR_ALIASED."""
    op = getattr(getattr(instr, "src", None), "operation", None)
    return getattr(op, "name", None) == "MLIL_VAR_ALIASED"


def collect_mem(instr: Any, func: Any, facts: Facts) -> None:
    """Depending on the instruction, handle memory version changes or VAR_ALIASED uses only."""
    if instr.ssa_memory_version != instr.ssa_memory_version_after:
        collect_mem_version_change(instr, func, facts)
    elif is_var_aliased(instr):
        collect_use_mem(instr, func, facts)


def collect_m2v_ssa(ssa: Any, func: Any, facts: Facts) -> None:
    if ssa.src.operation.name == "MLIL_VAR_ALIASED":
        addr = ssa.address
        func_name = func.name
        var_name = naming_var(ssa.dest, func_name)
        mem_name = naming_mem(ssa.ssa_memory_version_after, func_name)
        ensure_registered(func_name, var_name)
        ensure_registered(func_name, mem_name)
        facts.m2v.append(M2V(addr=addr, func=func_name, mem=mem_name, var=var_name))
        

def collect_v2m_ssa(ssa: Any, func: Any, facts: Facts) -> None:
    if ssa.ssa_memory_version != ssa.ssa_memory_version_after:
        addr = ssa.address
        func_name = func.name
        var_name = naming_var(ssa.src, func_name)
        mem_name = naming_mem(ssa.ssa_memory_version_after, func_name)
        ensure_registered(func_name, var_name)
        ensure_registered(func_name, mem_name)
        facts.v2m.append(V2M(addr=addr, func=func_name, var=var_name, mem=mem_name))


def add_mem_phi_def(instr: Any, func: Any, facts: Facts) -> str:
    """For MEM_PHI, add exactly one def_mem for dest_memory and return that memory name."""
    func_name = func.name
    def_name = naming_mem(instr.dest_memory, func_name)
    add_def_mem(instr.address, func_name, def_name, facts)
    return def_name


def add_mem_phi_use_and_edge(
    instr: Any, func: Any, def_name: str, src: int, facts: Facts
) -> None:
    """For each src_memory of MEM_PHI, add one use_mem and one MEdge to the def."""
    addr = instr.address
    func_name = func.name
    use_name = naming_mem(src, func_name)
    add_use_mem(addr, func_name, use_name, facts)
    facts.m_edges.append(
        MEdge(a1=addr, f1=func_name, m1=use_name, a2=addr, f2=func_name, m2=def_name)
    )


def collect_mem_phi(instr: Any, func: Any, facts: Facts) -> None:
    """For a MEM_PHI instruction: add one def_mem, and for each src add use_mem and an MEdge."""
    def_name = add_mem_phi_def(instr, func, facts)
    for src in instr.src_memory or ():
        add_mem_phi_use_and_edge(instr, func, def_name, src, facts)


def collect_use_mem(instr: Any, func: Any, facts: Facts) -> None:
    """Add exactly one use_mem for the instruction's ssa_memory_version."""
    func_name = func.name
    mem_name = naming_mem(instr.ssa_memory_version, func_name)
    add_use_mem(instr.address, func_name, mem_name, facts)


# ---------------------------------------------------------------------------
# Call: source/sink classification and parameter/memory collection
# ---------------------------------------------------------------------------

def is_src_site(call_name: str) -> bool:
    return any(entry[0] in call_name for entry in _SRC_KEYWORDS)


def is_sink_site(call_name: str) -> bool:
    return any(entry[0] in call_name for entry in _SINK_KEYWORDS)


def add_src_site(instr: Any, caller_func: Any, target_func: Any, facts: Facts) -> None:
    addr = instr.address
    callee_name = target_func.name
    caller_name = caller_func.name
    params = instr.params or ()
    for entry in _SRC_KEYWORDS:
        if entry[0] not in callee_name:
            continue
        param_idx = entry[1]
        if param_idx >= len(params):
            continue
        src_var = params[param_idx]
        src_var_name = naming_var(src_var, caller_name)
        src_mem_name = naming_mem(instr.ssa_memory_version_after, caller_name)
        ensure_registered(caller_name, src_var_name)
        ensure_registered(caller_name, src_mem_name)
        facts.srcs.append(SrcFact(addr=addr, call_name=caller_name))
        facts.src_vars.append(
            SrcVarFact(addr=addr, call_name=caller_name, var=src_var_name)
        )
        facts.src_mems.append(
            SrcMemFact(addr=addr, call_name=caller_name, mem=src_mem_name)
        )


def add_sink_site(instr: Any, caller_func: Any, target_func: Any, facts: Facts) -> None:
    addr = instr.address
    callee_name = target_func.name
    caller_name = caller_func.name
    params = instr.params or ()
    for entry in _SINK_KEYWORDS:
        if entry[0] not in callee_name:
            continue
        param_idx = entry[1]
        if param_idx >= len(params):
            continue
        sink_var = params[param_idx]
        sink_var_name = naming_var(sink_var, caller_name)
        sink_mem_name = naming_mem(instr.ssa_memory_version_after, caller_name)
        ensure_registered(caller_name, sink_var_name)
        ensure_registered(caller_name, sink_mem_name)
        facts.sinks.append(SinkFact(addr=addr, call_name=caller_name))
        facts.sink_vars.append(
            SinkVarFact(addr=addr, call_name=caller_name, var=sink_var_name))
        facts.sink_mems.append(
            SinkMemFact(addr=addr, call_name=caller_name, mem=sink_mem_name)
        )


def resolve_callee(caller_func: Any, instr: Any) -> Any | None:
    """Return the callee function from a call instruction, or None if it cannot be resolved."""
    callee_addr = instr.dest.constant
    return caller_func.view.get_function_at(callee_addr)


def ensure_call_registered(caller_func: Any, target_func: Any) -> None:
    """Register caller and callee function names into the mappers."""
    ensure_registered(target_func.name, caller_func.name)


def record_src_sink(instr: Any, caller_func: Any, target_func: Any, facts: Facts) -> None:
    """If the call is a source/sink site, record it into facts."""
    add_src_site(instr, caller_func, target_func, facts)
    add_sink_site(instr, caller_func, target_func, facts)


def handle_call(caller_func: Any, instr: Any, facts: Facts) -> None:
    """For a single CALL instruction, dispatch callee resolution, source/sink recording, and parameter/memory collection."""
    target_func = resolve_callee(caller_func, instr)
    if target_func is None:
        collect_mem(instr, caller_func, facts)
        return

    ensure_call_registered(caller_func, target_func)
    record_src_sink(instr, caller_func, target_func, facts)
    collect_param(instr, caller_func, target_func, facts)
    collect_mem(instr, caller_func, facts)


def get_use_instr(callee_func: Any, ssa_var: Any) -> Any | None:
    """Return the first instruction that uses the SSA variable, or None if none exists."""
    mlil_ssa = callee_func.mlil.ssa_form
    use_instrs = mlil_ssa.get_ssa_var_uses(ssa_var)
    return use_instrs[0] if use_instrs else None


def add_param_edge(
    actual_param: Any,
    formal_param: Any,
    ctx: CallContext,
    facts: Facts,
) -> None:
    """Add exactly one VEdge for a single pair of actual and formal parameters."""
    ssa_var = binaryninja.mediumlevelil.SSAVariable(formal_param, 0)
    use_instr = get_use_instr(ctx.target_func, ssa_var)
    if use_instr is None:
        return
    callee_addr = use_instr.address
    actual_name = naming_var(actual_param, ctx.caller_func_name)
    formal_name = naming_var(ssa_var, ctx.callee_func_name)
    ensure_registered(ctx.caller_func_name, actual_name)
    ensure_registered(ctx.callee_func_name, formal_name)
    facts.v_edges.append(
        VEdge(
            a1=ctx.caller_addr,
            f1=ctx.caller_func_name,
            v1=actual_name,
            a2=callee_addr,
            f2=ctx.callee_func_name,
            v2=formal_name,
        )
    )


def collect_param(instr: Any, caller_func: Any, target_func: Any, facts: Facts) -> None:
    """For a single call site, add Def–Use VEdges for all parameters."""
    ctx = CallContext(
        caller_addr=instr.address,
        caller_func_name=caller_func.name,
        callee_func_name=target_func.name,
        target_func=target_func,
    )
    actual_params = instr.params or ()
    formal_params = target_func.parameter_vars or ()
    for actual, formal in zip(actual_params, formal_params):
        add_param_edge(actual, formal, ctx, facts)


# ---------------------------------------------------------------------------
# Return: connect variables/memory between call site and return site 
# ---------------------------------------------------------------------------

def get_ssa_instrs_at_addr(func: Any, addr: int) -> list[Any]:
    """Return the list of SSA instructions at address addr within the function."""
    ssa = func.mlil.ssa_form
    return [i for i in ssa.instructions if i.address == addr]


def iter_return_sites(
    bv: BinaryView, callee_func: Any
) -> Iterator[tuple[Any, int, list[Any]]]:
    """Iterate over all (caller_func, caller_addr, SSA instructions at that address) that call the callee."""
    for ref in bv.get_code_refs(callee_func.start) or ():
        caller_func = ref.function
        caller_addr = ref.address
        caller_instrs = get_ssa_instrs_at_addr(caller_func, caller_addr)
        yield caller_func, caller_addr, caller_instrs


def handle_return(bv: BinaryView, callee_func: Any, callee_instr: Any, facts: Facts) -> None:
    """For a single RET instruction, connect only the return variable/memory edges for all call sites of this function."""
    for caller_func, _caller_addr, caller_instrs in iter_return_sites(bv, callee_func):
        for caller_instr in caller_instrs:
            ctx = ReturnSiteContext(
                caller_func=caller_func,
                caller_instr=caller_instr,
                callee_func=callee_func,
                callee_instr=callee_instr,
            )
            collect_return_vars(ctx, facts)
            collect_return_mems(ctx, facts)


def add_return_var_edge(
    callee_side: tuple[Any, str, Any],
    caller_side: tuple[Any, str, Any],
    facts: Facts,
) -> None:
    """Add exactly one VEdge for a single return value (callee def → caller use).
    callee_side/caller_side = (instr, func_name, var).
    """
    callee_instr, callee_func_name, callee_var = callee_side
    caller_instr, caller_func_name, caller_var = caller_side
    callee_name = naming_var(callee_var, callee_func_name)
    caller_name = naming_var(caller_var, caller_func_name)
    ensure_registered(caller_func_name, caller_name)
    ensure_registered(callee_func_name, callee_name)
    facts.v_edges.append(
        VEdge(
            a1=callee_instr.address,
            f1=callee_func_name,
            v1=callee_name,
            a2=caller_instr.address,
            f2=caller_func_name,
            v2=caller_name,
        )
    )


def ret_src_as_list(callee_instr: Any) -> list[Any]:
    """Return the src of MLIL_RET as a list (wrap a single value as [x], or convert an existing sequence to a list)."""
    if callee_instr.operation.name != "MLIL_RET":
        return []
    src = callee_instr.src
    if src is None:
        return []
    if isinstance(src, (str, bytes)):
        return []
    if hasattr(src, "__iter__") and not isinstance(src, (str, bytes)):
        return list(src)
    return [src]


def collect_return_vars(ctx: ReturnSiteContext, facts: Facts) -> None:
    """For a single call site, add VEdges from callee return values to caller vars_written."""
    callee_ret_vars = ret_src_as_list(ctx.callee_instr)
    caller_written = list(ctx.caller_instr.vars_written or ())
    for callee_var, caller_var in zip(callee_ret_vars, caller_written):
        callee_side = (ctx.callee_instr, ctx.callee_func.name, callee_var)
        caller_side = (ctx.caller_instr, ctx.caller_func.name, caller_var)
        add_return_var_edge(callee_side, caller_side, facts)


def collect_return_mems(ctx: ReturnSiteContext, facts: Facts) -> None:
    """For a single call site, add one MEdge from callee post-return memory to caller memory."""
    caller_mem = naming_mem(
        ctx.caller_instr.ssa_memory_version_after, ctx.caller_func.name
    )
    callee_mem = naming_mem(
        ctx.callee_instr.ssa_memory_version_after, ctx.callee_func.name
    )
    mem_def_instr = find_mem_def_site(ctx.callee_instr, ctx.callee_func, facts)
    if mem_def_instr is not None:
        callee_instr = mem_def_instr
    else:
        callee_instr = ctx.callee_instr
    ensure_registered(ctx.caller_func.name, caller_mem)
    ensure_registered(ctx.callee_func.name, callee_mem)
    facts.m_edges.append(
        MEdge(
            a1=callee_instr.address,
            f1=ctx.callee_func.name,
            m1=callee_mem,
            a2=ctx.caller_instr.address,
            f2=ctx.caller_func.name,
            m2=caller_mem,
        )
    )

def find_mem_def_site(ret_instr: Any, func: Any, facts: Facts) -> None:
    mlil = func.mlil
    if mlil is None:
        return
    for block in mlil.ssa_form.basic_blocks:
        for instr in block:
            if instr.ssa_memory_version != instr.ssa_memory_version_after and \
                ret_instr.ssa_memory_version == instr.ssa_memory_version_after:
                return instr

