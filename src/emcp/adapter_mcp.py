"""
EMCP Adapter: wraps legacy Anthropic MCP JSON-RPC servers with PlatSec and Token Budgeting.
Supports in-memory dispatchers and real external OS processes over stdio (pipes).
"""

from __future__ import annotations
import json
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional

from .constants import Capability, EmcpError
from .server import EmcpServer


class McpLegacyAdapter(EmcpServer):
    """
    Exposes an in-memory legacy Anthropic MCP server as an EMCP service with Tool-PIN,
    PlatSec capability enforcement, and Token Budget Escrow.
    """

    def __init__(
        self,
        name: str,
        jsonrpc_dispatcher: Callable[[Dict[str, Any]], Any],
        tool_capabilities: Optional[Dict[str, Capability]] = None,
        allowed_capabilities: Capability = Capability.NONE,
    ):
        super().__init__(name=name, allowed_capabilities=allowed_capabilities)
        self.dispatcher = jsonrpc_dispatcher
        self.tool_capabilities = tool_capabilities or {}
        self._import_mcp_tools()

    def _import_mcp_tools(self) -> None:
        """Discovers tools exposed by the underlying MCP JSON-RPC server."""
        try:
            req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            resp = self.dispatcher(req)
            tools = resp.get("result", {}).get("tools", [])
            for t in tools:
                t_name = t["name"]
                t_desc = t.get("description", "")
                t_schema = t.get("inputSchema", {})
                req_caps = self.tool_capabilities.get(t_name, Capability.NONE)

                def make_handler(name: str):
                    def handler(**kwargs):
                        call_req = {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": kwargs},
                        }
                        call_resp = self.dispatcher(call_req)
                        if "error" in call_resp:
                            raise RuntimeError(call_resp["error"].get("message", "MCP error"))
                        return call_resp.get("result", {})

                    return handler

                self.tool(
                    name=t_name,
                    description=t_desc,
                    required_caps=req_caps,
                    input_schema=t_schema,
                )(make_handler(t_name))

        except Exception:
            pass


class McpStdioProcessAdapter(EmcpServer):
    """
    Spawns an actual Anthropic MCP server executable as a child OS process over stdio pipes.
    Executes the JSON-RPC 2.0 handshake, discovers tools, and wraps execution in PlatSec
    capability bitmasks and Token Budget Escrow.

    Wire I/O runs off the event loop: a dedicated reader thread parses stdout
    and dispatches responses by JSON-RPC id, so concurrent tool calls pipeline
    in a single child process (the previous design serialized every request
    behind one lock and blocked the loop on readline).
    """

    def __init__(
        self,
        name: str,
        command: List[str],
        tool_capabilities: Optional[Dict[str, Capability]] = None,
        allowed_capabilities: Capability = Capability.NONE,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_ms: int = 30_000,
    ):
        super().__init__(name=name, allowed_capabilities=allowed_capabilities)
        self.command = command
        self.tool_capabilities = tool_capabilities or {}
        self.timeout_s = timeout_ms / 1000.0
        self._write_lock = threading.Lock()
        self._dispatch_lock = threading.Lock()
        self._pending: Dict[int, Dict[str, Any]] = {}
        self._req_id = 0

        # Launch MCP process. Binary pipes + manual line framing: text mode
        # pays encoding/line-buffering per line on the hot path.
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

        self._reader = threading.Thread(
            target=self._read_loop, name=f"emcp-mcp-reader-{name}", daemon=True
        )
        self._reader.start()

        self._handshake()
        self._import_tools()

    # -- JSON-RPC over stdio ---------------------------------------------

    def _read_loop(self) -> None:
        """Parses stdout and dispatches each response to its waiting thread."""
        proc = self.proc
        stdout = proc.stdout
        stderr = proc.stderr
        assert stdout is not None and stderr is not None
        # Drain stderr so the 64KB pipe buffer can never block the child.
        threading.Thread(
            target=lambda: [None for _ in iter(lambda: stderr.readline(), b"")],
            daemon=True,
        ).start()
        while True:
            line = stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8"))
            except Exception:
                continue
            rid = msg.get("id")
            if rid is None:
                continue  # server notification: nothing is awaiting it
            with self._dispatch_lock:
                slot = self._pending.pop(rid, None)
            if slot is not None:
                slot["resp"] = msg
                slot["event"].set()

        # EOF: fail every in-flight request.
        with self._dispatch_lock:
            slots = list(self._pending.values())
            self._pending.clear()
        for slot in slots:
            slot["err"] = RuntimeError("MCP child process closed stdout unexpectedly")
            slot["event"].set()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _write_line(self, req: Dict[str, Any]) -> None:
        if self.proc.poll() is not None:
            raise RuntimeError("MCP child process is not running")
        if not self.proc.stdin:
            raise RuntimeError("Process stdin unavailable")
        data = (json.dumps(req) + "\n").encode("utf-8")
        with self._write_lock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        req: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        self._write_line(req)

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends a JSON-RPC request and blocks (in a worker thread) until
        the matching response arrives. Concurrent calls pipeline: only the
        stdin write is serialized, never the round-trip."""
        rid = self._next_id()
        slot: Dict[str, Any] = {"event": threading.Event()}
        with self._dispatch_lock:
            self._pending[rid] = slot
        req: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            req["params"] = params
        try:
            self._write_line(req)
        except Exception:
            with self._dispatch_lock:
                self._pending.pop(rid, None)
            raise
        if not slot["event"].wait(timeout=self.timeout_s):
            with self._dispatch_lock:
                self._pending.pop(rid, None)
            if not slot["event"].is_set():
                raise TimeoutError(f"MCP request {method} timed out after {self.timeout_s:.1f}s")
        if "err" in slot:
            raise slot["err"]
        return slot["resp"]

    def _handshake(self) -> None:
        """Executes official Anthropic MCP protocol initialization handshake."""
        resp = self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "emcp-bridge", "version": "0.1.0"},
            },
        )
        if not resp or "result" not in resp:
            raise RuntimeError(f"MCP handshake failed: {resp}")

        self._notify("notifications/initialized")

    def _import_tools(self) -> None:
        """Queries tools/list over stdio and binds each tool into EMCP."""
        resp = self._request("tools/list", {})
        if not resp:
            return

        tools = resp.get("result", {}).get("tools", [])
        for t in tools:
            t_name = t["name"]
            t_desc = t.get("description", "")
            t_schema = t.get("inputSchema", {})
            req_caps = self.tool_capabilities.get(t_name, Capability.NONE)

            def make_handler(name: str):
                def handler(**kwargs):
                    call_resp = self._request(
                        "tools/call",
                        {"name": name, "arguments": kwargs},
                    )
                    if not call_resp or "error" in call_resp:
                        err_msg = call_resp["error"].get("message", "MCP error") if call_resp else "Empty response"
                        raise RuntimeError(err_msg)

                    res = call_resp.get("result", {})
                    # If MCP returns standard content array, extract text
                    if "content" in res and isinstance(res["content"], list):
                        texts = [item.get("text", "") for item in res["content"] if item.get("type") == "text"]
                        if texts:
                            return {"text": "\n".join(texts)}
                    return res

                return handler

            self.tool(
                name=t_name,
                description=t_desc,
                required_caps=req_caps,
                input_schema=t_schema,
            )(make_handler(t_name))

    def close(self) -> None:
        """Terminates the underlying child process."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self._reader is not None and self._reader.is_alive():
            self._reader.join(timeout=1.0)
