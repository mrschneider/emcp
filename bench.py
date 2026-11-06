"""Quick before/after micro-benchmarks for the EMCP hot paths."""
import asyncio
import statistics
import sys
import time

sys.path.insert(0, "src")

from emcp import EmcpClient, EmcpServer, EmcpFrame, ToolConstraints
from emcp.security import ToolIdentity
from emcp.dtn import ToolBundle, ToolCustodyStore
from emcp.qos import ToolOwnershipArbitrator

N = 2000


def bench(label, fn, n=N):
    # warmup
    for _ in range(20):
        fn()
    ts = []
    for _ in range(10):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        ts.append((time.perf_counter() - t0) / n * 1e6)
    med = statistics.median(ts)
    print(f"{label:42s} {med:9.2f} us/op")
    return med


big = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}
small = {"a": "x", "n": 1}

# 1. Frame pack/unpack
f_big = EmcpFrame(verb="tools/call", args=big, constraints=ToolConstraints(token_budget=4000))
f_small = EmcpFrame(verb="echo", args=small, constraints=ToolConstraints(token_budget=4000))
wire_big = f_big.pack()
wire_small = f_small.pack()

bench("frame.pack (big 64KB)", lambda: f_big.pack())
bench("frame.pack (small)", lambda: f_small.pack())
bench("frame.unpack (big 64KB)", lambda: EmcpFrame.unpack(wire_big))
bench("frame.unpack (small)", lambda: EmcpFrame.unpack(wire_small))

# 2. Sign/verify
ident = ToolIdentity.generate()
signed = EmcpFrame(verb="echo", args=big, constraints=ToolConstraints(token_budget=4000))
ident.sign_frame(signed)
bench("sign_frame (big)", lambda: ident.sign_frame(signed))
bench("verify_frame (in-proc, cached)", lambda: ident.verify_frame(signed))
unpacked_signed = EmcpFrame.unpack(signed.pack())
bench("verify_frame (wire, unpacked)", lambda: ident.verify_frame(unpacked_signed))

# 3. Server round-trip
server = EmcpServer(name="bench")


@server.tool(name="echo")
def echo(a: str = ""):
    return {"echo": a}


async def rt():
    client = EmcpClient()
    return await client.call_tool(server, "echo", {"a": "x" * 100})


def rt_fn():
    asyncio.get_event_loop().run_until_complete(rt())


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
bench("server round-trip (small)", rt_fn, n=500)

# 4. DTN + arbitrator
store = ToolCustodyStore(1, max_bundles=100_000, max_storage_bytes=1 << 30)
b = ToolBundle(1, 1, 2, 0, 0.0, lifetime_s=10_000.0, payload=b"x" * 64)
bench("dtn.admit_bundle", lambda: store.admit_bundle(b, now=0.0))
store2 = ToolCustodyStore(1, max_bundles=100_000, max_storage_bytes=1 << 30)
for i in range(20_000):
    store2.admit_bundle(ToolBundle(i, 1, 2, 0, 0.0, lifetime_s=10_000.0), now=0.0)
bench("dtn.prune_expired (20k live)", lambda: store2.prune_expired(now=1.0))

arb = ToolOwnershipArbitrator()
for i in range(5000):
    arb.register_candidate(f"t{i}", 1, strength=1, lease_ms=10_000, now=0.0)
bench("qos.heartbeat (pin->5000 tools)", lambda: arb.heartbeat(1, now=1.0))
