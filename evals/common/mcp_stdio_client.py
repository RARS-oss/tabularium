"""A minimal raw JSON-RPC client over `tabularium serve`'s stdio, for measuring the one thing
the CLI-based tabularium_client.py structurally cannot: latency inside one *long-lived* process,
the way a real MCP host (Claude Code, Cursor) actually talks to the server -- one model load, many
calls -- as opposed to every CLI invocation being a fresh process that reloads the ONNX embedder
from scratch.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from tabularium_client import binary


class McpStdioSession:
    def __init__(self, vault_dir: Path):
        spawn_start = time.perf_counter()
        self.proc = subprocess.Popen(
            [binary(), "--vault", str(vault_dir), "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._id = 0
        # Cmd::Serve embeds any missing vectors (loading the ONNX model) *before* it starts
        # answering JSON-RPC at all, so this handshake round-trip -- not the first tool call --
        # is where the CLI's per-invocation model-load cost actually shows up for a server.
        self._request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "eval", "version": "1"}})
        self._notify("notifications/initialized", {})
        self.startup_sec = time.perf_counter() - spawn_start

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _write(self, obj: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read(self) -> dict:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"tabularium serve closed stdout unexpectedly; stderr: {err[:2000]}")
        return json.loads(line)

    def _request(self, method: str, params: dict) -> dict:
        req_id = self._next_id()
        self._write({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        return self._read()

    def _notify(self, method: str, params: dict) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        resp = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in resp:
            raise RuntimeError(f"{name}: {resp['error']}")
        content = resp["result"].get("structuredContent")
        return content if content is not None else resp["result"]

    def timed_call(self, name: str, arguments: Optional[dict] = None) -> tuple[float, dict]:
        start = time.perf_counter()
        result = self.call_tool(name, arguments)
        return time.perf_counter() - start, result

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
