# Architecture

## Overview

The toolkit contains two independent CLI tools sharing no runtime code:

```
pcap-reader   ──► reads pcap/pcapng ──► formats output (text / JSON / CSV)
pcap-playback ──► reads pcap/pcapng ──► timing engine ──► network interface
```

## Python Tool Layout

Each tool uses the `src` layout:

```
python/<tool>/
├── pyproject.toml
└── src/
    └── <package>/
        ├── __init__.py     version string
        ├── __main__.py     python -m entry point
        ├── cli.py          click commands (depends on rich, click)
        └── reader.py       core logic — no CLI dependency
            player.py
```

The core logic modules (`reader.py`, `player.py`) import only stdlib and scapy. This keeps them independently testable and usable as a library without pulling in CLI dependencies.

## Packet Pipeline

```
File on disk
     │
     ▼
  rdpcap()              scapy reads raw bytes → Packet objects
     │
     ▼
 Iterator[PacketRecord]  typed dataclass; abstracts scapy internals
     │
     ├──► CLI formatter  (rich Table / JSON dumps / CSV writer)
     └──► Sender         (scapy sendp / dry-run noop)
```

## Timing Engine (Playback)

Inter-packet delays are derived from capture timestamps:

```python
gap = (pkt[i].time - pkt[i-1].time) / rate_multiplier
time.sleep(max(0, gap))
```

- `rate_multiplier = 1.0` → real-time replay
- `rate_multiplier = 2.0` → 2× speed (halved gaps)
- `rate_multiplier = 0`   → maximum throughput (no sleeping)

## Error Strategy

| Scenario | Behaviour |
|----------|----------|
| File not found | Exception → CLI prints error → exit 1 |
| Malformed packet | Log warning, skip, continue |
| Interface not found | Exception from scapy → CLI prints error → exit 2 |
| Permission denied (raw socket) | Exception from scapy → CLI prints error → exit 2 |

## Dependency Graph

```
cli.py
  └── reader.py / player.py
        └── scapy

cli.py also imports:
  ├── click   (command parsing)
  └── rich    (terminal formatting)
```
