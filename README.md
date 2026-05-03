# pcap-playback

A toolkit for replaying PCAP/PCAPNG network capture files — the kind exported from Wireshark or captured with `tcpdump`/`tshark`.

## Tools

| Tool | Language | Status | Description |
|------|----------|--------|-------------|
| [`pcap-playback`](python/pcap_playback/) | Python | **Ready** | Replay captures to a live network interface |
| `pcap-reader` | Python | Planned | Inspect and summarize capture files |
| `pcap-playback` | Rust | Planned | High-performance replay engine |

## Quick Start

```bash
# 1. Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Install the playback tool
cd python/pcap_playback
uv sync

# 3. Preview what's in a capture file (no root needed)
uv run pcap-playback preview capture.pcap

# 4. Dry run — verify options without sending anything
uv run pcap-playback play capture.pcap --dry-run

# 5. Live replay (requires root for raw packet sending)
sudo uv run pcap-playback play capture.pcap --interface eth0
```

For full usage documentation see **[python/pcap_playback/README.md](python/pcap_playback/README.md)**.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- `libpcap` — usually pre-installed on Linux/macOS. For live replay only; `--dry-run` and `preview` work without it.
- Root / sudo — for live packet sending only

## Repository Layout

```
.
├── python/
│   ├── pcap_playback/    # Python playback tool (ready)
│   └── pcap_reader/      # Python reader tool (planned)
├── rust/                 # Rust implementations (Phase 4+)
├── docs/                 # Architecture notes
└── DEVELOPMENT_PLAN.md   # Roadmap
```
