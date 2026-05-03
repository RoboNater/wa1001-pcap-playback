# pcap-playback

Replay PCAP/PCAPNG network capture files — the kind exported from Wireshark or captured with `tcpdump`/`tshark` — back onto the network.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.12+ | |
| [uv](https://docs.astral.sh/uv/) | Fast Python package manager |
| libpcap | Only needed for `--mode raw`. Linux: `apt install libpcap-dev`. macOS: `brew install libpcap` |
| Root / sudo | Only needed for `--mode raw` (live Layer-2 sending) |

---

## Installation

```bash
cd python/pcap_playback
uv sync
```

`uv` creates an isolated virtual environment and installs all dependencies.

---

## Replay modes

The tool has two modes, selected with `--mode`:

| Mode | Default? | Root required? | What it does |
|------|----------|----------------|--------------|
| `socket` | **Yes** | No | Sends UDP payloads and reassembled TCP streams using normal OS sockets. The OS handles routing — no interface needed. |
| `raw` | No | **Yes** | Full Layer-2 replay via scapy. Every header (src IP, TTL, flags, …) is sent exactly as captured. |

**When to use which:**
- Use **socket mode** (default) for replaying application traffic at a service — HTTP, DNS, database queries, etc. No root required.
- Use **raw mode** when you need byte-for-byte wire fidelity: load testing network equipment, replaying non-TCP/UDP protocols (ICMP, ARP), or forensic replay.

### Socket mode behaviour
- **UDP**: each packet's payload is sent to the original destination IP:port, preserving inter-packet timing.
- **TCP**: packets in the same flow (src IP:port → dst IP:port) are reassembled into one stream and sent as a single TCP connection at the time of the flow's first data packet.
- **Other protocols** (ICMP, ARP, etc.) are skipped — use `--mode raw` for those.
- The source IP is whatever the OS assigns (your machine's outbound IP). Use `--dst-rewrite` to redirect traffic to a different host.

---

## Commands

### `preview` — inspect a file before replaying

Always start here. Shows a table of the first N packets without touching the network. No root required.

```bash
uv run pcap-playback preview capture.pcap
uv run pcap-playback preview capture.pcap --count 50
uv run pcap-playback preview capture.pcap --filter "tcp port 80"
```

Example output:
```
                        capture.pcap — preview
 #      Timestamp                Src               Dst               Proto  Len  Summary
 1      2024-01-15 10:00:00.000  192.168.1.10      8.8.8.8           DNS    74   DNS Qry "example.com"
 2      2024-01-15 10:00:00.012  8.8.8.8           192.168.1.10      DNS    106  DNS Ans "93.184.216.34"
```

---

### `play` — replay a file once

```bash
# Dry run — shows what would be sent; no root, no network
uv run pcap-playback play capture.pcap --dry-run

# Socket mode (default) — sends to original destinations, no root needed
uv run pcap-playback play capture.pcap

# Redirect all traffic to a different host
uv run pcap-playback play capture.pcap --dst-rewrite 192.168.1.50

# Double speed
uv run pcap-playback play capture.pcap --rate-multiplier 2.0

# Maximum speed (no inter-packet delay)
uv run pcap-playback play capture.pcap --rate-multiplier 0

# Only replay UDP DNS traffic
uv run pcap-playback play capture.pcap --filter "udp port 53"

# Raw mode — full Layer-2 replay (requires root)
sudo uv run pcap-playback play capture.pcap --mode raw --interface eth0
```

---

### `loop` — replay continuously

Replays the file over and over until Ctrl-C. Useful for sustained load generation.

```bash
uv run pcap-playback loop capture.pcap
uv run pcap-playback loop capture.pcap --dst-rewrite 192.168.1.50 --rate-multiplier 0
sudo uv run pcap-playback loop capture.pcap --mode raw --interface eth0
```

---

## All options

### `play`

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--mode` | `-m` | `socket` | `socket` (no root) or `raw` (requires root) |
| `--interface` | `-i` | system default | Interface for raw mode only (e.g. `eth0`, `en0`) |
| `--rate-multiplier` | `-r` | `1.0` | Speed: `1.0`=real-time, `2.0`=double, `0`=max |
| `--filter` | | none | BPF filter — only replay matching packets |
| `--count` | `-n` | all | Stop after N packets |
| `--dst-rewrite` | | none | Replace destination IP addresses |
| `--src-rewrite` | | none | Replace source IP addresses (raw mode only) |
| `--dry-run` | | off | Count without sending anything |
| `--verbose` / `-v` | | off | Show debug logging |

### `preview`

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--count` | `-n` | `20` | Rows to display |
| `--filter` | | none | BPF filter |

### `loop`

Accepts `--mode`, `--interface`, `--rate-multiplier`, `--filter`, `--dst-rewrite`, `--src-rewrite`.

---

## BPF filter expressions

BPF is the same filter syntax used in Wireshark and tcpdump.

| Expression | Matches |
|------------|---------|
| `tcp` | All TCP packets |
| `udp` | All UDP packets |
| `tcp port 80` | TCP on port 80 (either direction) |
| `host 192.168.1.1` | Any packet to or from this host |
| `src host 10.0.0.1` | Packets from this source only |
| `not arp` | Everything except ARP |
| `tcp port 443 or tcp port 80` | HTTPS and HTTP |

---

## Common use cases

**Replay HTTP traffic at a test server (no root):**
```bash
uv run pcap-playback play prod-capture.pcap \
    --dst-rewrite 192.168.1.50 \
    --filter "tcp port 80"
```

**Replay DNS queries at a test resolver (no root):**
```bash
uv run pcap-playback play capture.pcap \
    --dst-rewrite 10.0.0.1 \
    --filter "udp port 53"
```

**Generate sustained load at maximum speed (no root):**
```bash
uv run pcap-playback loop capture.pcap --dst-rewrite 10.0.0.1 --rate-multiplier 0
```

**Preview a capture, then dry-run to verify options:**
```bash
uv run pcap-playback preview capture.pcap
uv run pcap-playback play capture.pcap --dst-rewrite 10.0.0.1 --filter "udp" --dry-run
```

**Full wire-fidelity replay (raw mode, requires root):**
```bash
sudo uv run pcap-playback play capture.pcap --mode raw --interface eth0
```

---

## Troubleshooting

**`Operation not permitted` / `Permission denied`**
You're using `--mode raw` without root. Either add `sudo`, or switch to the default socket mode (drop the `--mode raw` flag).

**TCP connections refused**
In socket mode, the tool tries to connect to the original destination IP:port. If nothing is listening there, connections will fail and be counted as skipped. Use `--dst-rewrite` to point at your test server, and make sure the service is running.

**Only UDP packets sent, TCP skipped**
TCP flows are sent as complete streams. If the capture only has SYN/FIN/ACK packets with no application payload, there is nothing to send. Check with `preview` first.

**`No such device` / interface not found (raw mode)**
Check the interface name with `ip link show` (Linux) or `ifconfig -l` (macOS). Common names: `eth0`, `ens3`, `en0`, `lo`.

**Packets skipped (shown in final stats)**
Individual send failures are non-fatal. Run with `--verbose` to see per-packet error messages.
