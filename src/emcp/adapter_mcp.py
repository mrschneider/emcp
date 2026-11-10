"""
EMCP Adapter: wraps legacy Anthropic MCP JSON-RPC servers with PlatSec and Token Budgeting.
Supports in-memory dispatchers and real external OS processes over stdio (pipes).
"""

from __future__ import annotations
import asyncio
import queue
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional

from .constants import Capability, EmcpError
from .frame import _dumps, _loads
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
        max_pending_requests: int = 256,
    ):
        super().__init__(name=name, allowed_capabilities=allowed_capabilities)
        if max_pending_requests < 1:
            raise ValueError("max_pending_requests must be positive")
        self.max_pending_requests = max_pending_requests
        self._closed = False
        self._writes = queue.Queue(maxsize=max_pending_requests)
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

        try:
            self._handshake()
            self._import_tools()
        except BaseException:
            self.close()
            raise
        self._writer = threading.Thread(target=self._write_loop, daemon=True,
                                        name=f"emcp-mcp-writer-{name}")
        self._writer.start()

    # -- JSON-RPC over stdio ---------------------------------------------

    def _read_loop(self) -> None:
        """Parses stdout and dispatches each response to its waiting thread."""
        proc = self.proc
        stdout = proc.stdout
        stderr = proc.stderr
        assert stdout is not None and stderr is not None
        # Drain stderr so the 64KB pipe buffer can never block the child.
        self._stderr_reader = threading.Thread(
            target=self._drain_stderr, daemon=True,
            name=f"emcp-mcp-stderr-{self.name}",
        )
        self._stderr_reader.start()
        while True:
            line = stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                # orjson fast path when available (see frame._loads): the
                # reader thread parses every MCP response here, and the
                # native bytes decode is ~2x faster than stdlib json.loads.
                msg = _loads(line)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            rid = msg.get("id")
            if rid is None:
                continue  # server notification: nothing is awaiting it
            with self._dispatch_lock:
                slot = self._pending.pop(rid, None)
            if slot is not None:
                self._complete(slot, response=msg)

        self._fail_pending(RuntimeError("MCP child process closed stdout unexpectedly"))

    def _drain_stderr(self) -> None:
        # Fixed-size reads bound memory even for stderr without newlines.
        assert self.proc.stderr is not None
        while self.proc.stderr.read(65536):
            pass

    @staticmethod
    def _complete(slot, response=None, error=None) -> None:
        if "future" in slot:
            def deliver():
                future = slot["future"]
                if not future.done():
                    if error is not None:
                        future.set_exception(error)
                    else:
                        future.set_result(response)
            try:
                slot["loop"].call_soon_threadsafe(deliver)
            except RuntimeError:
                pass  # owning loop has already closed
        else:
            if error is not None:
                slot["err"] = error
            else:
                slot["resp"] = response
            slot["event"].set()

    def _fail_pending(self, error) -> None:
        with self._dispatch_lock:
            self._closed = True
            slots = list(self._pending.values())
            self._pending.clear()
        for slot in slots:
            self._complete(slot, error=error)

    def _register_request(self, slot) -> int:
        with self._dispatch_lock:
            if self._closed:
                raise RuntimeError("MCP adapter is closed")
            if len(self._pending) >= self.max_pending_requests:
                raise RuntimeError("MCP pending request limit exceeded")
            self._req_id += 1
            rid = self._req_id
            self._pending[rid] = slot
            return rid

    def _write_loop(self) -> None:
        while not self._closed:
            try:
                item = self._writes.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is None:
                return
            rid, req = item
            with self._dispatch_lock:
                if rid not in self._pending:
                    continue  # timed out or cancelled before writing
            try:
                self._write_line(req)
            except Exception as error:
                with self._dispatch_lock:
                    slot = self._pending.pop(rid, None)
                if slot is not None:
                    self._complete(slot, error=error)

    async def _request_async(self, method, params=None):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        rid = self._register_request({"future": future, "loop": loop})
        req = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            req["params"] = params
        try:
            # A dedicated writer handles pipe backpressure; neither a pending
            # response nor a blocked pipe occupies the shared executor.
            try:
                self._writes.put_nowait((rid, req))
            except queue.Full as error:
                raise RuntimeError("MCP write queue limit exceeded") from error
            try:
                return await asyncio.wait_for(future, self.timeout_s)
            except asyncio.TimeoutError as error:
                raise TimeoutError(f"MCP request {method} timed out after {self.timeout_s:.1f}s") from error
        finally:
            with self._dispatch_lock:
                self._pending.pop(rid, None)
            future.cancel()

    def _write_line(self, req: Dict[str, Any]) -> None:
        if self.proc.poll() is not None:
            raise RuntimeError("MCP child process is not running")
        if not self.proc.stdin:
            raise RuntimeError("Process stdin unavailable")
        # Shared codec (frame._dumps): orjson when available, stdlib json
        # otherwise. JSON-RPC requests are strings/ints/dicts, so the
        # compact orjson encoding is wire-compatible.
        data = _dumps(req) + b"\n"
        with self._write_lock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        req: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        self._write_line(req)

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Blocking startup handshake/discovery; tool calls use _request_async."""
        slot: Dict[str, Any] = {"event": threading.Event()}
        rid = self._register_request(slot)
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
                async def handler(**kwargs):
                    call_resp = await self._request_async(
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
        self._fail_pending(RuntimeError("MCP adapter is closed"))
        try:
            self._writes.put_nowait(None)
        except queue.Full:
            pass
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=1.0)
                except Exception:
                    pass
        if self._reader is not None and self._reader.is_alive():
            self._reader.join(timeout=1.0)
        writer = getattr(self, "_writer", None)
        if writer is not None and writer.is_alive():
            writer.join(timeout=1.0)
        stderr_reader = getattr(self, "_stderr_reader", None)
        if stderr_reader is not None and stderr_reader.is_alive():
            stderr_reader.join(timeout=1.0)
        # Close each pipe only after its I/O thread exits; closing a buffered
        # stream while another thread holds its lock can block shutdown.
        for stream, thread in ((self.proc.stdin, writer),
                               (self.proc.stdout, self._reader),
                               (self.proc.stderr, stderr_reader)):
            if stream is not None and (thread is None or not thread.is_alive()):
                stream.close()
