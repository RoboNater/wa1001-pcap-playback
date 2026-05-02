# pcap-playback

Replay PCAP/PCAPNG network capture files — the kind exported from Wireshark or captured with `tcpdump`/`tshark` — back onto a live network interface.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.12+ | |
| [uv](https://docs.astral.sh/uv/) | Fast Python package manager |
| libpcap | Linux/macOS: usually pre-installed. Install with `apt install libpcap-dev` or `brew install libpcap` |
| Root / admin | Required for live packet sending. Not required for `--dry-run` or `preview`. |

---

## Installation

```bash
# From the repo root
cd python/pcap_playback
uv sync
```

That's it. `uv` creates an isolated virtual environment and installs all dependencies including scapy.

---

## Commands

### `preview` — inspect a file before replaying

Always start here. Shows a table of the first N packets without touching the network.

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
 3      2024-01-15 10:00:00.025  192.168.1.10      93.184.216.34     TCP    74   TCP SYN
...
Showing 20 of 1 843 packet(s)
```

---

### `play` — replay to a network interface

Sends packets onto an interface, preserving the original inter-packet timing by default.

**Requires root/sudo for live sending.** Use `--dry-run` to test without privileges.

```bash
# Dry run first — no packets sent, no root required
uv run pcap-playback play capture.pcap --dry-run

# Live replay (requires root)
sudo uv run pcap-playback play capture.pcap --interface eth0

# Double speed
sudo uv run pcap-playback play capture.pcap --interface eth0 --rate-multiplier 2.0

# Maximum speed (no inter-packet delay)
sudo uv run pcap-playback play capture.pcap --interface eth0 --rate-multiplier 0

# Only replay the first 100 packets
sudo uv run pcap-playback play capture.pcap --interface eth0 --count 100

# Only replay TCP traffic (BPF filter)
sudo uv run pcap-playback play capture.pcap --interface eth0 --filter "tcp"

# Rewrite IP addresses before sending
sudo uv run pcap-playback play capture.pcap --interface eth0 \
    --src-rewrite 10.0.0.1 \
    --dst-rewrite 10.0.0.2
```

**Finding your interface name:**
```bash
# Linux
ip link show
# macOS
ifconfig -l
```

---

### `loop` — replay continuously

Replays the file over and over until you press Ctrl-C. Useful for sustained load generation.

```bash
sudo uv run pcap-playback loop capture.pcap --interface eth0
sudo uv run pcap-playback loop capture.pcap --interface eth0 --rate-multiplier 0.5
```

Output:
```
Looping capture.pcap — press Ctrl-C to stop
  [1] 1 843 packets, 2 187 432 bytes, 12.401s
  [2] 1 843 packets, 2 187 432 bytes, 12.388s
  ^C
Stopped after 2 iteration(s).
```

---

## All Options

### `play`

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--interface` | `-i` | system default | Network interface to send on (e.g. `eth0`, `en0`) |
| `--rate-multiplier` | `-r` | `1.0` | Speed: `1.0`=real-time, `2.0`=double speed, `0`=max speed |
| `--filter` | | none | BPF filter — only replay matching packets (e.g. `"tcp port 443"`) |
| `--count` | `-n` | all | Stop after this many packets |
| `--src-rewrite` | | none | Replace all source IP addresses with this value |
| `--dst-rewrite` | | none | Replace all destination IP addresses with this value |
| `--dry-run` | | off | Count and display stats without sending anything |
| `--verbose` / `-v` | | off | Show debug logging |

### `preview`

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--count` | `-n` | `20` | Number of packets to show |
| `--filter` | | none | BPF filter |

### `loop`

Accepts `--interface`, `--rate-multiplier`, `--filter`, `--src-rewrite`, `--dst-rewrite`.

---

## BPF Filter Expressions

BPF (Berkeley Packet Filter) is the same filter syntax used in Wireshark and tcpdump.

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

## Common Use Cases

**Test a service with real traffic from a production capture:**
```bash
sudo uv run pcap-playback play prod-capture.pcap \
    --interface eth0 \
    --dst-rewrite 192.168.1.50 \
    --filter "tcp port 8080"
```

**Generate sustained load for benchmarking:**
```bash
sudo uv run pcap-playback loop capture.pcap \
    --interface eth0 \
    --rate-multiplier 0
```

**Check what's in a capture file before touching the network:**
```bash
uv run pcap-playback preview capture.pcap --count 100
```

**Replay at half speed for debugging:**
```bash
sudo uv run pcap-playback play capture.pcap --interface lo --rate-multiplier 0.5
```

---

## Troubleshooting

**`Operation not permitted` / `Permission denied`**
Live packet sending requires root. Run with `sudo`, or use `--dry-run` to verify the file and options first.

**`No such device` / interface not found**
Check the interface name with `ip link show` (Linux) or `ifconfig -l` (macOS). Common names: `eth0`, `ens3`, `en0`, `lo`.

**Scapy warning about no default route**
You can safely ignore this when using `--dry-run`. For live replay, specify `--interface` explicitly.

**Packets skipped (shown in final stats)**
Individual send failures are non-fatal. Run with `--verbose` to see per-packet error messages.
