# Specification: PCAP Playback Toolkit

## 1. Overview

The PCAP Playback Toolkit provides CLI tools for analyzing and replaying network packet captures. Primary use cases:

- Network debugging and post-mortem analysis
- Functional testing by replaying known-good traffic
- Load simulation against test environments
- Protocol research and education

## 2. Supported File Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| PCAP classic | `.pcap` | Original libpcap format |
| PCAPNG | `.pcapng` | Next-generation; multiple interfaces, metadata |
| ERF | `.erf` | Endace format (stretch goal) |

## 3. Tool: pcap-reader

### 3.1 Purpose

Read, inspect, filter, and summarize the contents of a PCAP/PCAPNG file without replaying it.

### 3.2 Commands

```
pcap-reader info <file>      Print file metadata (format, packet count, duration)
pcap-reader summary <file>   Protocol breakdown and top talkers
pcap-reader list <file>      Tabular packet list with timestamps, src/dst, proto, length
pcap-reader filter <file>    Apply BPF filter and output matching packets
pcap-reader export <file>    Export packets to JSON, CSV, or text
```

### 3.3 Options (shared)

| Flag | Description |
|------|-------------|
| `--filter TEXT` | BPF filter expression |
| `--output FILE` | Write to file instead of stdout |
| `--format [text\|json\|csv]` | Output format (default: text) |
| `--count N` | Limit to first N packets |
| `--verbose / -v` | Increase verbosity |

### 3.4 Sample Output (`list`)

```
#     Timestamp                Src IP           Dst IP           Proto   Len   Info
1     2024-01-15 10:00:00.000  192.168.1.10     8.8.8.8          DNS     74    Query: example.com
2     2024-01-15 10:00:00.012  8.8.8.8          192.168.1.10     DNS     106   Response: 93.184.216.34
```

## 4. Tool: pcap-playback

### 4.1 Purpose

Replay packets from a PCAP/PCAPNG file to a live network interface, preserving or scaling timing.

### 4.2 Commands

```
pcap-playback play <file>     Replay packets to an interface
pcap-playback loop <file>     Replay continuously until Ctrl-C
pcap-playback preview <file>  Dry-run: show what would be sent
```

### 4.3 Options

| Flag | Description |
|------|-------------|
| `--interface IFACE` | Network interface (e.g. `eth0`) |
| `--rate-multiplier FLOAT` | Speed multiplier (1.0=real-time, 0=max speed) |
| `--filter TEXT` | BPF filter — only replay matching packets |
| `--count N` | Replay only first N packets |
| `--dry-run` | Preview without sending |
| `--verbose / -v` | Increase verbosity |

### 4.4 Timing Model

Inter-packet delays are derived from pcap timestamps:

```
gap = (pkt[i].time - pkt[i-1].time) / rate_multiplier
sleep(max(0, gap))
```

With `--rate-multiplier 0` all delays are skipped (maximum throughput).

## 5. Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Input file error (not found, unreadable, malformed) |
| 2 | Interface error (not found, permission denied) |
| 3 | Other / unexpected error |

## 6. Error Handling

- Malformed packets: log warning, skip, continue (non-fatal)
- Missing/unreadable input: clear error message, exit 1
- Interface errors: clear error message with hint, exit 2
- All errors go to stderr; output goes to stdout

## 7. Non-Goals (v1)

- GUI or graphical interface
- Live capture from interface (read-only from files)
- Deep application-layer protocol decoding
- Capture file editing or anonymization
- Distributed/multi-host replay
