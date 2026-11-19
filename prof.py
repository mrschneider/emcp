"""Component profiler: break down the hot paths into their raw parts."""
import sys, time, statistics, hashlib
sys.path.insert(0, "src")
from emcp import EmcpFrame, ToolConstraints
from emcp.security import ToolIdentity

N = 5000
big = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}  # ~64KB

def bench(label, fn, n=N, w=50):
    for _ in range(w):
        fn()
    ts = []
    for _ in range(10):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        ts.append((time.perf_counter() - t0) / n * 1e6)
    ts.sort()
    print(f"{label:46s} {ts[len(ts)//2]:9.2f} us/op")

ident = ToolIdentity.generate()

# --- sign components ---
f = EmcpFrame(verb="echo", args=big, constraints=ToolConstraints(token_budget=4000))
wire = f.pack()  # prime cache
slots = f.pack_slots()
bench("raw Ed25519.sign (64KB payload)", lambda: ident.sign(slots))
bench("sign_frame (big, cached slots)", lambda: ident.sign_frame(f))

# --- verify components ---
ident.sign_frame(f)  # prime _signed_bytes cache + ref
bench("raw Ed25519.verify (sig over 64KB)", lambda: ident.verify(slots, f.envelope.signature))
bench("verify_frame (in-proc, cached)", lambda: ident.verify_frame(f))

# --- SHA512 cost over 64KB ---
bench("SHA-512 over 64KB (raw)", lambda: hashlib.sha512(slots).digest())

# --- unpack components ---
bench("raw orjson.loads (64KB)", lambda: __import__("orjson").loads(f.__dict__.get("_args_json")))
bench("frame.unpack (big 64KB)", lambda: EmcpFrame.unpack(wire))

# --- server round-trip pieces ---
from emcp import EmcpServer, EmcpClient
import asyncio
server = EmcpServer(name="p")

@server.tool(name="echo")
def echo(a: str = ""):
    return {"echo": a}

async def rt():
    c = EmcpClient()
    return await c.call_tool(server, "echo", {"a": "x" * 100})

async def _rt_bench():
    for _ in range(20):
        await rt()
    ts = []
    for _ in range(10):
        t0 = time.perf_counter()
        for _ in range(500):
            await rt()
        ts.append((time.perf_counter() - t0) / 500 * 1e6)
    ts.sort()
    print(f"{'server round-trip (small)':46s} {ts[len(ts)//2]:9.2f} us/op")

asyncio.run(_rt_bench())
