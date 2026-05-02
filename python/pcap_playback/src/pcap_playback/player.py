"""Core replay logic for pcap-playback."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# Module-level imports so tests can patch pcap_playback.player.rdpcap / sendp
try:
    from scapy.utils import rdpcap
    from scapy.sendrecv import sendp
except ImportError:  # pragma: no cover
    rdpcap = None  # type: ignore[assignment]
    sendp = None  # type: ignore[assignment]


def _require_scapy() -> None:
    if rdpcap is None:
        raise RuntimeError("scapy is required: uv add --project python/pcap_playback scapy")


@dataclass
class PlaybackStats:
    packets_sent: int = 0
    packets_skipped: int = 0
    bytes_sent: int = 0
    elapsed_seconds: float = 0.0


def load_packets(path: Path, bpf_filter: str | None = None) -> list[object]:
    """Read packets from a pcap/pcapng file, optionally applying a BPF filter."""
    _require_scapy()
    if bpf_filter:
        from scapy.all import sniff  # type: ignore[import-untyped]
        return list(sniff(offline=str(path), filter=bpf_filter))
    return list(rdpcap(str(path)))  # type: ignore[misc]


def rewrite_addresses(pkt: object, src_ip: str | None, dst_ip: str | None) -> object:
    """Return a copy of pkt with IP src/dst rewritten and checksums cleared."""
    if src_ip is None and dst_ip is None:
        return pkt
    from scapy.layers.inet import IP  # type: ignore[import-untyped]
    from scapy.packet import Packet  # type: ignore[import-untyped]

    p: Packet = pkt.copy()  # type: ignore[union-attr]
    if p.haslayer(IP):
        ip = p[IP]
        if src_ip:
            ip.src = src_ip
        if dst_ip:
            ip.dst = dst_ip
        # Clear stale checksums so scapy recalculates on build
        del ip.chksum
        if hasattr(ip.payload, "chksum"):
            del ip.payload.chksum
    return p


def replay(
    path: Path,
    interface: str | None = None,
    rate_multiplier: float = 1.0,
    bpf_filter: str | None = None,
    count: int | None = None,
    dry_run: bool = False,
    src_rewrite: str | None = None,
    dst_rewrite: str | None = None,
    on_packet: Callable[[int, object], None] | None = None,
) -> PlaybackStats:
    """
    Replay packets from a pcap file.

    rate_multiplier=0  → send at maximum speed (no inter-packet delay).
    dry_run=True       → count packets/bytes but do not transmit.
    on_packet          → called as on_packet(packet_number, packet) for each packet.
    """
    _require_scapy()

    packets = load_packets(path, bpf_filter)
    stats = PlaybackStats()
    start_wall = time.monotonic()
    prev_pkt_time: float | None = None

    for i, raw_pkt in enumerate(packets):
        if count is not None and i >= count:
            break

        pkt_time = float(raw_pkt.time)  # type: ignore[attr-defined]

        # Preserve inter-packet timing, scaled by rate_multiplier
        if prev_pkt_time is not None and rate_multiplier > 0:
            gap = (pkt_time - prev_pkt_time) / rate_multiplier
            if gap > 0:
                time.sleep(gap)
        prev_pkt_time = pkt_time

        pkt = rewrite_addresses(raw_pkt, src_rewrite, dst_rewrite)

        if on_packet:
            on_packet(i + 1, pkt)

        if dry_run:
            stats.packets_sent += 1
            stats.bytes_sent += len(pkt)  # type: ignore[arg-type]
        else:
            try:
                sendp(pkt, iface=interface, verbose=False)  # type: ignore[misc]
                stats.packets_sent += 1
                stats.bytes_sent += len(pkt)  # type: ignore[arg-type]
            except Exception as exc:
                logger.warning("Failed to send packet %d: %s", i + 1, exc)
                stats.packets_skipped += 1

    stats.elapsed_seconds = time.monotonic() - start_wall
    return stats
