# pcap-playback

A toolkit for reading, inspecting, and replaying PCAP/PCAPNG network capture files from Wireshark/tshark.

## Tools

| Tool | Language | Status | Description |
|------|----------|--------|-------------|
| `pcap-reader` | Python | Active | Inspect, filter, and summarize capture files |
| `pcap-playback` | Python | Active | Replay captures to a live interface or target |
| `pcap-reader` | Rust | Planned | High-performance reader |
| `pcap-playback` | Rust | Planned | High-performance replay engine |

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) — fast Python package manager
- `libpcap` (Linux/macOS) or Npcap (Windows) for live replay

## Quick Start

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Inspect a capture file
cd python/pcap_reader
uv run pcap-reader info capture.pcap
uv run pcap-reader list capture.pcap

# Replay to an interface
cd python/pcap_playback
uv run pcap-playback play capture.pcap --interface eth0
uv run pcap-playback play capture.pcap --dry-run
```

## Repository Layout

```
.
├── python/
│   ├── pcap_reader/      # Python reader tool (uv project)
│   └── pcap_playback/    # Python playback tool (uv project)
├── rust/                 # Rust implementations (Phase 4+)
├── tests/fixtures/       # Shared test capture files
└── docs/                 # Architecture and design docs
```

## Development

See [SPECIFICATION.md](SPECIFICATION.md) for technical requirements and [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for the roadmap.

Agents and AI assistants: read [AGENTS.md](AGENTS.md) before contributing.
