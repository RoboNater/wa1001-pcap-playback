# Development Plan

## Phase 0 — Scaffold ✅

- [x] Repository structure and uv workspace
- [x] AGENTS.md, CLAUDE.md, SPECIFICATION.md
- [x] pyproject.toml for both Python tools
- [x] src-layout with stub modules and tests
- [x] docs/architecture.md

---

## Phase 1 — Python Playback

**Goal**: A fully working `pcap-playback` CLI. This is the primary deliverable.

> `pcap-playback` has no dependency on `pcap-reader` — both tools call scapy directly and are independently installable.

### Tasks

- [ ] `player.py` — complete `replay()` with accurate timing engine
- [ ] `player.py` — address rewriting support (`--src-rewrite`, `--dst-rewrite`)
- [ ] `cli.py` — `play` command (interface, rate-multiplier, filter, count, dry-run)
- [ ] `cli.py` — `loop` command (continuous replay until Ctrl-C)
- [ ] `cli.py` — `preview` command (dry-run table of what would be sent)
- [ ] `tests/` — unit tests with mocked scapy (no live interface required)
- [ ] Add sample `.pcap` fixture to `tests/fixtures/`
- [ ] End-to-end smoke test with `--dry-run`

**Acceptance criteria**: `uv run --project python/pcap_playback pcap-playback play capture.pcap --interface lo --dry-run` runs without error and reports correct packet and byte counts.

---

## Phase 2 — Python Reader

**Goal**: A fully working `pcap-reader` CLI (useful for inspection/debugging, not required for playback).

### Tasks

- [ ] `reader.py` — complete `read_packets()` with BPF filter support
- [ ] `reader.py` — complete `get_capture_info()` with protocol breakdown
- [ ] `cli.py` — `info` command
- [ ] `cli.py` — `list` command (text / JSON / CSV output)
- [ ] `cli.py` — `summary` command
- [ ] `cli.py` — `filter` command (write filtered pcap)
- [ ] `cli.py` — `export` command
- [ ] `tests/` — unit tests with fixture pcap files

**Acceptance criteria**: `uv run --project python/pcap_reader pcap-reader list capture.pcap` produces a formatted packet table with correct timestamps, addresses, and protocols.

---

## Phase 3 — Polish & Integration

- [ ] BPF filter support in both tools
- [ ] JSON/CSV export in reader
- [ ] Rich progress bars for long playback operations
- [ ] Hardened error handling (all exit codes from spec)
- [ ] Integration tests with real pcap fixtures
- [ ] Complete README with full examples
- [ ] `ruff check` and `mypy` clean across both projects

---

## Phase 4 — Rust Playback

**Goal**: Port `pcap-playback` to Rust for performance (mirrors Phase 1 priority).

### Key crates

- `pcap` — libpcap bindings
- `pnet` — packet parsing
- `clap` — CLI
- `indicatif` — progress bars

### Tasks

- [ ] Create `rust/pcap-playback/` Cargo project
- [ ] Implement timing engine in Rust
- [ ] Raw socket / pcap replay
- [ ] Benchmark vs Python playback

---

## Phase 5 — Rust Reader

**Goal**: Port `pcap-reader` to Rust.

### Tasks

- [ ] Create `rust/pcap-reader/` Cargo project
- [ ] Implement `info` and `list` subcommands
- [ ] JSON output parity with Python version
- [ ] Benchmark vs Python reader

---

## Milestones

| Milestone | Phase | Status |
|-----------|-------|--------|
| Repo scaffold | 0 | ✅ Done |
| Python playback MVP | 1 | 🔄 In progress |
| Python reader MVP | 2 | ⬜ Pending |
| Polish & integration | 3 | ⬜ Pending |
| Rust playback | 4 | ⬜ Pending |
| Rust reader | 5 | ⬜ Pending |
