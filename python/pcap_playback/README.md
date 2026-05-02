# pcap-playback

CLI tool to replay PCAP/PCAPNG network capture files to a live network interface.

## Usage

```bash
uv run pcap-playback play capture.pcap --interface eth0
uv run pcap-playback play capture.pcap --dry-run
uv run pcap-playback preview capture.pcap
uv run pcap-playback loop capture.pcap --rate-multiplier 2.0
```

## Options

| Flag | Description |
|------|-------------|
| `--interface / -i` | Network interface (e.g. `eth0`) |
| `--rate-multiplier / -r` | Speed: 1.0=real-time, 0=max speed |
| `--filter` | BPF filter expression |
| `--count / -n` | Stop after N packets |
| `--src-rewrite IP` | Rewrite source IP |
| `--dst-rewrite IP` | Rewrite destination IP |
| `--dry-run` | Count without transmitting |
