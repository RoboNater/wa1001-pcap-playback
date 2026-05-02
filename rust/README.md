# Rust Tools (Phase 4+)

High-performance Rust implementations of `pcap-reader` and `pcap-playback` will live here.

## Planned Structure

```
rust/
├── Cargo.toml            # workspace
├── pcap-reader/
│   ├── Cargo.toml
│   └── src/main.rs
└── pcap-playback/
    ├── Cargo.toml
    └── src/main.rs
```

## Key Crates

| Crate | Purpose |
|-------|---------|
| [`pcap`](https://crates.io/crates/pcap) | libpcap bindings |
| [`pnet`](https://crates.io/crates/pnet) | Packet parsing |
| [`clap`](https://crates.io/crates/clap) | CLI |
| [`serde_json`](https://crates.io/crates/serde_json) | JSON output |
| [`indicatif`](https://crates.io/crates/indicatif) | Progress bars |

Development begins after Python tools reach Phase 3 stability.
