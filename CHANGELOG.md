# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Added
- `ToolIdentity.verify_frame()` / `verify()` and
  `EmcpServer.register_identity()` for the opt-in signature path.
- `tests/test_perf_critical.py` regression suite locking the four contracts.

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

