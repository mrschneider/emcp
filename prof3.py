"""End-to-end request-path profiler (async round-trip)."""
import sys, time, asyncio
sys.path.insert(0, "src")
from emcp import EmcpServer, EmcpClient
from emcp.security import ToolIdentity

big = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}


def make(sign_frames):
    server = EmcpServer(name="p")

    @server.tool(name="echo")
    def echo(a=""):
        return a

    ident = ToolIdentity.generate()
    client = EmcpClient(identity=ident, sign_frames=sign_frames)
    return server, client


async def run(sign_frames, N=2000, W=50):
    server, client = make(sign_frames)
    for _ in range(W):
        await client.call_tool(server, "echo", {"a": big})
    ts = []
    for _ in range(N):
        t0 = time.perf_counter()
        await client.call_tool(server, "echo", {"a": big})
        ts.append((time.perf_counter() - t0) * 1e3)
    ts.sort()
    label = f"roundtrip 64KB signed" if sign_frames else "roundtrip 64KB unsigned"
    print(f"{label:34s} p50={ts[len(ts)//2]*1000:.2f}us "
          f"p99={ts[int(0.99*len(ts))]*1000:.2f}us "
          f"avg={sum(ts)/len(ts):.0f}us")


async def main():
    await run(False)
    await run(True)

asyncio.run(main())
