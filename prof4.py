"""Breakdown of the signed 64KB round-trip."""
import sys, time, asyncio
sys.path.insert(0, "src")
from emcp import EmcpServer, EmcpClient, EmcpFrame, ToolConstraints, FrameFlags
from emcp.security import ToolIdentity

big = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}


def bench(label, fn, n=2000, w=50):
    for _ in range(w):
        fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1e3)
    ts.sort()
    print(f"{label:42s} p50={ts[len(ts)//2]*1000:.2f}us "
          f"p99={ts[int(0.99*len(ts))]*1000:.2f}us "
          f"avg={sum(ts)/len(ts):.1f}us")


async def main():
    server = EmcpServer(name="p")

    @server.tool(name="echo")
    def echo(a=""):
        return a

    ident = ToolIdentity.generate()
    client = EmcpClient(identity=ident, sign_frames=True)

    def mk():
        return client._build_request_frame(server, 4, "echo", big,
                                           ToolConstraints(token_budget=4000),
                                           FrameFlags.FLAG_SIGNED)

    f = mk()
    bench("client.sign_frame (64KB)", lambda: ident.sign_frame(f))
    ident.sign_frame(f)
    bench("server.verify_frame (cached)", lambda: ident.verify_frame(f))

    reply = f.create_reply(status=0, result_data=big, remaining_budget=0)
    bench("create_reply (64KB)", lambda: f.create_reply(status=0, result_data=big, remaining_budget=0))
    bench("reply.pack (64KB)", lambda: reply.pack())

asyncio.run(main())
