"""Core replay logic for pcap-playback."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class PlaybackStats:
    packets_sent: int = 0
    packets_skipped: int = 0
    bytes_sent: int = 0
    elapsed_seconds: float = 0.0


def replay(
    path: Path,
    interface: str | None = None,
    rate_multiplier: float = 1.0,
    bpf_filter: str | None = None,
    count: int | None = None,
    dry_run: bool = False,
    on_packet: Callable[[int, object], None] | None = None,
) -> PlaybackStats:
    """
    Replay packets from a pcap file.

    When dry_run=True no packets are transmitted; useful for previewing.
    on_packet(packet_number, scapy_packet) is called for each packet processed.
    """
    try:
        from scapy.utils import rdpcap  # type: ignore[import-untyped]
        from scapy.sendrecv import sendp  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError("scapy is required: uv add scapy") from exc

    packets = rdpcap(str(path))
    stats = PlaybackStats()
    start_wall = time.monotonic()
    prev_pkt_time: float | None = None

    for i, pkt in enumerate(packets):
        if count is not None and i >= count:
            break

        pkt_time = float(pkt.time)  # type: ignore[attr-defined]

        if prev_pkt_time is not None and rate_multiplier > 0:
            gap = (pkt_time - prev_pkt_time) / rate_multiplier
            if gap > 0:
                time.sleep(gap)

        prev_pkt_time = pkt_time

        if on_packet:
            on_packet(i + 1, pkt)

        if dry_run:
            stats.packets_sent += 1
            stats.bytes_sent += len(pkt)
        else:
            try:
                sendp(pkt, iface=interface, verbose=False)  # type: ignore[arg-type]
                stats.packets_sent += 1
                stats.bytes_sent += len(pkt)
            except Exception as exc:
                logger.warning("Failed to send packet %d: %s", i + 1, exc)
                stats.packets_skipped += 1

    stats.elapsed_seconds = time.monotonic() - start_wall
    return stats
