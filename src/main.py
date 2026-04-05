#!/usr/bin/env python3

import argparse
import sys

from constraint import Facts, dump_facts
from extractor import extract
from edge_builder import build_edges
from facts_graph import build_facts_graph, report_reachability_alarms
from taint_solver import solve
from visualize import serve_graph


def analyze_with_z3(facts: Facts) -> None:
    dump_facts(facts)
    for (addr, func, var) in solve(facts):
        print(f"[ALARM] {func} @ 0x{addr:x}  var={var}")


def analyze_with_reachability(facts: Facts) -> None:
    report_reachability_alarms(facts, build_facts_graph(facts))


def load_binaryninja():
    try:
        import binaryninja
    except ImportError:
        print("Error: binaryninja module not found.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Install the Binary Ninja Python API with:", file=sys.stderr)
        print(
            "  python3 [BinaryNinja install directory]/scripts/install_api.py",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        sys.exit(1)

    return binaryninja


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Headless Binary Ninja MLIL instruction iterator (test harness)."
    )
    parser.add_argument(
        "input",
        help="Path to input binary to analyze",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--vis",
        action="store_true",
        help="Start a visualization server at http://localhost:7777",
    )
    mode.add_argument(
        "--z3",
        action="store_true",
        help="Run Z3 fixedpoint (datalog) taint analysis and print alarms",
    )
    mode.add_argument(
        "--reach",
        action="store_true",
        help="Run graph reachability (prune + path); default when --vis and --z3 are omitted",
    )
    return parser.parse_args()


def run_pipeline(bn, input_path: str, args: argparse.Namespace) -> None:
    with bn.load(input_path) as bv:
        bv.update_analysis_and_wait()
        facts = extract(bv)
        build_edges(facts)

        if args.vis:
            serve_graph(facts, port=7777)
            return

        if args.z3:
            analyze_with_z3(facts)
            return

        analyze_with_reachability(facts)


def main() -> None:
    args = parse_args()

    bn = load_binaryninja()

    try:
        run_pipeline(bn, args.input, args)
    except Exception as e:
        print(f"Error: Failed to open '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
