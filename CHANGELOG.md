# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-11-02

### Changed
- MCP stdio tool calls await futures instead of holding default-executor workers.
  A dedicated writer handles pipe backpressure; `max_pending_requests` defaults
  to 256 and bounds in-flight requests and queued writes.
- Tool results use the fast frame JSON encoder, with cached bytes reused by
  reply packing. Unicode is emitted as UTF-8; token usage is calculated from
  actual encoded bytes. Unicode and finite-number formatting can change budget
  boundaries. Unsupported values and potentially normalized non-finite numbers
  retain stdlib serialization compatibility.
- Ownership arbitration selects the strongest live candidate in one pass,
  preserving the higher-PIN tie-break without allocating and sorting a list.

### Fixed
- DTN expiry now uses an ordered heap, handling mixed lifetimes and preserving
  the exact lifetime boundary. Empty pruning is constant-time; periodic heap
  compaction bounds tombstones from early custody releases.
- Child stderr is discarded in fixed-size chunks instead of retaining one list
  entry per line for the child process lifetime.
- MCP cancellation, timeout, EOF, write failures, and shutdown clear pending
  requests; cancellation also refunds the server's token escrow. Shutdown stops
  I/O threads and closes their pipes.

### Validation
- 58 Python tests pass, including 17 new resource and lifecycle regressions.
- Local representative measurements: empty DTN pruning remains about 0.1 µs
  from 100 to 100,000 bundles; a 123 KB result call plus reply packing improved
  from about 748 µs to 195 µs. These are local measurements, not throughput guarantees.

## [0.5.0] - 2026-10-31

### Changed
- **`EmcpFrame.unpack` fast-path** — unpacking a frame used to route every one
  of its 14 fields through the dataclass `__setattr__` override, which runs a
  cache-invalidation check (a dict lookup + comparison) per field write. During
  unpack the fields are set once, in order, so that logic was pure overhead
  (~14 dict lookups per frame, ~40µs/frame at the top of the round-trip). Unpack
  now constructs the object with a `__new__`-based fast path that assigns each
  field via `object.__setattr__`, bypassing the invalidation logic entirely.
  Round-trip unpack drops from ~180µs to ~140µs (~22% faster). Behaviour is
  identical: the invalidation logic still runs on every *mutation* after unpack.
- **Optional `orjson`** — `frame.py` now uses `orjson` for its JSON
  (de)serialisation when it is installed, falling back to `json.dumps`/`json.loads`
  automatically. The wire format is byte-identical either way, so no caller or
  test changes. Install with `pip install -e ".[perf]"`. The perf regression
  suite passes with and without `orjson` present.

### Removed
- **`crates/emcp-daemon`** — a stub crate whose `main.rs` only parsed CLI args,
  called `tracing_subscriber::fmt::init()`, logged an init line and returned
  `Ok(())`. Every one of its dependencies (`tokio`, `clap`, `tracing`,
  `tracing-subscriber`, `serde_json`, `emcp-core`) was unused; it shipped no
  binary and implemented no relay or stdio proxy despite the README's
  "High-concurrency Tokio relay & stdio proxy" description. Removed it from the
  workspace and the CI Rust job now runs `cargo test -p emcp-core` only.
- **`cargo build --release --workspace`** from CI — the daemon stub was the
  only thing producing a release binary; `emcp-core` is a library crate with
  no binary target.

### Notes
- **`crates/emcp-core` is retained** as a *native reference implementation* of
  the EMCP wire format and its supporting primitives (PlatSec gate, token
  budget). It is **not** linked into the Python runtime — the Python layer
  (`frame.py`, `security.py`, `budget.py`) is the production path. Keeping it
  gives the binary spec an authoritative, testable second implementation and
  keeps the Rust CI job meaningful (three unit tests: budget escrow, PlatSec
  gate). See `Cargo.toml` for the full description.

## [0.4.0] - 2026-10-27

### Changed
- **Signature is opt-in** (`EmcpClient(sign_frames=True)` /
  `EmcpServer(verify_signatures=True)`) — Ed25519 signing cost ~40µs/frame
  in-process (65% of the round-trip) and was never verified. Signing now
  stays off on trusted in-process transports; when enabled, the server
  verifies via `register_identity()` and fails closed with
  `EMCP_ERR_UNKNOWN_PIN` / `EMCP_ERR_SIGNATURE_INVALID`.
- **`pack_slots` caches its single JSON pass** — `sign_frame` + `pack` used
  to run `json.dumps` twice on the same args; a 120KB frame dropped from
  2280µs to ~1470µs for sign+pack.
- **Sync tool handlers run in a worker thread** (`asyncio.to_thread`) so a
  blocking handler no longer stalls the event loop: two concurrent 300ms
  calls now take ~300ms instead of ~600ms. `iscoroutinefunction` is cached
  at registration.
- **`McpStdioProcessAdapter` pipelines JSON-RPC by id** — a dedicated reader
  thread dispatches responses to matching request ids (no more one-request-
  per-lock, no blocking `readline` on the event loop). Eight concurrent 50ms
  tool calls now complete in ~55ms against a concurrent MCP server instead
  of ~400ms serialized.
- **`TokenBudgetLedger.commit()` drops the escrow (Rust)** — the native
  ledger kept committed entries in `escrows` forever (one entry per tool
  call in a long-running daemon); it now mirrors the Python ledger, and a
  post-commit `spend()` correctly returns false.
- **`ToolOwnershipArbitrator.heartbeat()` is O(1)** — a reverse index
  (`pin -> tool names`) replaces the full scan of every tool's candidate
  table on every pulse; heartbeats are the hottest path in a mesh.
- **DTN `prune_expired()` is O(k log n)** — an `(expiry, bundle_id)`
  min-heap (lazy deletion) replaces the full table scan per call; and
  `admit_bundle()` now reclaims expired bundles before refusing a full
  store, so an aged buffer accepts new traffic instead of bouncing it.
- **`list_tools()` is cached** — the tool catalogue is built once and
  invalidated on registration (and on external `tools` dict mutation)
  instead of being rebuilt on every `tools/list` request.
- **Dead Rust deps removed** — `ed25519-dalek`, `sha2`, and `serde` were
  declared in `emcp-core` but never used (signing lives in the Python
  layer); Cargo.lock shrank from 86 to 61 packages.

### Added
- `ToolIdentity.verify_frame()` / `verify()` and
  `EmcpServer.register_identity()` for the opt-in signature path.
- `tests/test_perf_critical.py` regression suite locking the four critical
  contracts, and `tests/test_perf_medium.py` locking the five medium fixes
  (heartbeat reverse index, DTN prune/reclaim, list_tools cache).
- `emcp-core::budget::tests::test_escrows_dropped_on_commit_and_refund`
  regression test for the native ledger leak.

## [0.3.0] - 2026-10-26

### Changed
- **Single-JSON reply path** - the server encodes the tool result once, meters
  tokens on those bytes and stashes them for `pack_slots` to reuse: one JSON
  pass per successful call instead of `str()` + `dumps()`. In-process
  `reply.args` stays a dict; wire bytes identical.
- **DTN duplicate-suppression ring** evicts with `deque.popleft()` (O(1))
  instead of `list.pop(0)` (up to 5001-entry shift per bundle past capacity).
- **Budget ledger leak fix** - `TokenBudgetLedger.commit()` now pops the
  escrow; `_escrows` grew one entry per tool call forever in a long-running
  server, and a post-commit `spend()` now correctly returns False.
- **Native release profile** - `[profile.release]` with thin LTO and
  `codegen-units = 1` on the workspace root (release build ~40s).

### Fixed
- **Strict wire parsing** (spec conformance): the verb slot decodes strictly
  - malformed UTF-8 raises instead of being silently replaced -
  `unpack_slots` rejects declared slot lengths that exceed the payload
  instead of letting Python slicing absorb them, and `EmcpFrame`
  invalidates its parsed-wire and single-encode caches on any field
  mutation, so a mutated frame is re-encoded, never sent stale.

## [0.2.0] - 2026-09-30

### Added
- Initial staged release: python-dotenv runtime boot, QA file-read and
  environment gates (see git history for details).

