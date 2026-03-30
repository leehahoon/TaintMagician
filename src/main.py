#!/usr/bin/env python3

import argparse
import sys

from constraint import dump_facts
from extractor import extract
from edge_builder import build_edges
from taint_solver import solve
from visualize import serve_graph

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
    parser.add_argument(
        "--vis",
        action="store_true",
        help="Start a visualization server at http://localhost:7777 instead of running the solver",
    )
    return parser.parse_args()

def run_pipeline(bn, input_path: str, vis: bool = False) -> None:
    with bn.load(input_path) as bv:
        bv.update_analysis_and_wait()
        facts = extract(bv)
        build_edges(facts)
        if vis:
            serve_graph(facts, port=7777)
            return

        dump_facts(facts)
        alarms = solve(facts)
        for (addr, func, var) in alarms:
            print(f"[ALARM] {func} @ 0x{addr:x}  var={var}")

def main() -> None:
    args = parse_args()

    bn = load_binaryninja()

    # Open the binary (load returns a BinaryView; update_analysis is True by default)
    try:
        run_pipeline(bn, args.input, vis=args.vis)
    except Exception as e:
        print(f"Error: Failed to open '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

