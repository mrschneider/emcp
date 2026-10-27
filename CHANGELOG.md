# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Initial staged release: python-dotenv runtime boot, required-file assertion
  in `qa_runner.py`, `EMCP_ALLOW_ANY_BACKEND=1` escape hatch, GitHub Pages
  artifact-upload permission.

