from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from constraint import Facts


def _build_graph(facts: Facts) -> dict[str, Any]:
    """
    Build a simple graph representation from Facts.

    Nodes: variable names appearing in VEdges.
    Edges: directed def-use edges (from v1 -> v2).
    """
    nodes: dict[str, int] = {}
    edges: list[dict[str, Any]] = []

    def _get_node_id(name: str) -> int:
        if name not in nodes:
            nodes[name] = len(nodes)
        return nodes[name]

    for e in facts.v_edges:
        src_id = _get_node_id(e.v1)
        dst_id = _get_node_id(e.v2)
        edges.append(
            {
                "source": src_id,
                "target": dst_id,
                "a1": e.a1,
                "f1": e.f1,
                "a2": e.a2,
                "f2": e.f2,
            }
        )

    node_list: list[dict[str, Any]] = []
    for name, node_id in nodes.items():
        # Variable names are typically of the form "var#n@func".
        func_name = ""
        if "@" in name:
            _, func_name = name.split("@", 1)
        node_list.append(
            {
                "id": node_id,
                "name": name,
                "func": func_name,
            }
        )

    return {"nodes": node_list, "edges": edges}


def _load_index_html() -> str:
    """
    Load vis/index.html from the project root.

    Expected layout:
      project_root/
        vis/index.html
        src/visualize.py  (this file)
    """
    root = Path(__file__).resolve().parent.parent
    html_path = root / "vis" / "index.html"
    try:
        return html_path.read_text(encoding="utf-8")
    except OSError:
        return "<!DOCTYPE html><html><body><p>index.html not found.</p></body></html>"


def _make_handler(graph_json: str) -> type[BaseHTTPRequestHandler]:
    index_html = _load_index_html()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # type: ignore[override]
            if self.path == "/graph.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(graph_json.encode("utf-8"))
                return

            if self.path == "/" or self.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(index_html.encode("utf-8"))
                return

            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            # Quiet default logging
            return

    return Handler


def serve_graph(facts: Facts, host: str = "127.0.0.1", port: int = 7777) -> None:
    """
    Start a simple HTTP server that serves the graph visualization.

    This call blocks the current process until interrupted (Ctrl+C).
    """
    graph = _build_graph(facts)
    graph_json = json.dumps(graph)

    handler_cls = _make_handler(graph_json)
    server = HTTPServer((host, port), handler_cls)

    print(f"[VIS] Serving graph at http://{host}:{port} (Ctrl+C to stop)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

