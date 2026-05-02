# AGENTS.md

Guidance for AI coding agents (Claude, Copilot, Cursor, etc.) working in this repository.

## Project Purpose

This repository builds CLI tools to read and replay PCAP/PCAPNG network packet capture files.

1. `pcap-reader` — inspect, filter, and summarize packet captures
2. `pcap-playback` — replay captures onto a live network interface

Python tools are implemented first; high-performance Rust equivalents follow in Phase 4+.

## Repository Structure

```
python/pcap_reader/     uv-managed Python project for the reader tool
python/pcap_playback/   uv-managed Python project for the playback tool
rust/                   Rust workspace (Phase 4+, not yet started)
tests/fixtures/         Shared sample .pcap/.pcapng files for tests
docs/                   Architecture diagrams and design notes
```

## Working with Python Tools

Each Python tool is an independent uv project. Run commands from the repo root using `--project`:

```bash
# Run a tool
uv run --project python/pcap_reader pcap-reader --help
uv run --project python/pcap_playback pcap-playback --help

# Run tests
uv run --project python/pcap_reader pytest -v
uv run --project python/pcap_playback pytest -v

# Add a dependency
uv add --project python/pcap_reader <package>

# Lint
uv run --project python/pcap_reader ruff check src/
```

## Code Conventions

- Python 3.12+; type hints on all public functions
- Use `scapy` for packet parsing; `click` for CLI; `rich` for terminal output
- One module per concern: `reader.py`/`player.py` for core logic, `cli.py` for commands
- Core logic modules must not import `click` or `rich` — keep them library-friendly
- Tests go in `tests/` inside each project; use `pytest`
- Prefer `pathlib.Path` over `str` for file paths
- No `print()` in library code; use `logging`

## Key Libraries

| Library | Purpose |
|---------|--------|
| `scapy` | Packet parsing, crafting, sending |
| `click` | CLI framework |
| `rich` | Terminal formatting and tables |
| `pytest` | Testing |
| `ruff` | Linting |
| `mypy` | Static type checking |

## Testing

```bash
# Run all tests for a tool
uv run --project python/pcap_reader pytest -v

# With coverage
uv run --project python/pcap_reader pytest --cov=src --cov-report=term-missing
```

Test fixture files (`.pcap`) live in `tests/fixtures/`. Add new ones there when needed. Never use live network capture in tests.

## Checklist Before Committing

- [ ] `uv run --project <tool> ruff check src/` passes
- [ ] `uv run --project <tool> mypy src/` passes (or new code has type hints)
- [ ] `uv run --project <tool> pytest` passes
- [ ] New features have at least one test
- [ ] CLI `--help` output is accurate

## Phase Awareness

Consult [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for the current phase. Do not begin Rust work until Python tools reach Phase 3 stability.
