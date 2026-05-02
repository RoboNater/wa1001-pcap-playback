# CLAUDE.md

Claude Code guidance for this repository.

## Stack

- **Language**: Python 3.12 (Rust planned Phase 4+)
- **Package manager**: uv (not pip, not poetry)
- **CLI framework**: click
- **Packet library**: scapy
- **Output**: rich
- **Testing**: pytest
- **Linting**: ruff + mypy

## How to Run Things

```bash
# Reader tool
uv run --project python/pcap_reader pcap-reader --help
uv run --project python/pcap_reader pcap-reader info capture.pcap
uv run --project python/pcap_reader pcap-reader list capture.pcap

# Playback tool
uv run --project python/pcap_playback pcap-playback --help
uv run --project python/pcap_playback pcap-playback play capture.pcap --dry-run

# Tests
uv run --project python/pcap_reader pytest -v
uv run --project python/pcap_playback pytest -v

# Lint
uv run --project python/pcap_reader ruff check src/
uv run --project python/pcap_playback ruff check src/
```

## uv Workspace

The root `pyproject.toml` defines a uv workspace. Each tool under `python/` is a member. You can install all workspace deps at once:

```bash
uv sync
```

## Scapy Note

Scapy requires root/admin privileges for live packet sending (`sendp`). For testing, always use pcap fixture files rather than live capture. The `--dry-run` flag in `pcap-playback` bypasses sending entirely.

## Active Branch

`claude/setup-pcap-playback-project-Kg66b`
