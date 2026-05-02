"""Core packet-reading logic for pcap/pcapng files."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


@dataclass
class PacketRecord:
    number: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    summary: str


@dataclass
class CaptureInfo:
    path: Path
    packet_count: int
    start_time: float | None
    end_time: float | None
    duration_seconds: float | None
    protocols: dict[str, int] = field(default_factory=dict)

    @property
    def duration_str(self) -> str:
        if self.duration_seconds is None:
            return "unknown"
        return f"{self.duration_seconds:.3f}s"


def read_packets(
    path: Path,
    bpf_filter: str | None = None,
    count: int | None = None,
) -> Iterator[PacketRecord]:
    """Yield PacketRecord objects from a pcap/pcapng file."""
    try:
        from scapy.utils import rdpcap  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError("scapy is required: uv add scapy") from exc

    packets = rdpcap(str(path))

    for i, pkt in enumerate(packets):
        if count is not None and i >= count:
            break
        try:
            yield _packet_to_record(i + 1, pkt)
        except Exception as exc:
            logger.warning("Skipping malformed packet %d: %s", i + 1, exc)


def _packet_to_record(number: int, pkt: object) -> PacketRecord:
    from scapy.layers.inet import IP  # type: ignore[import-untyped]
    from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
    from scapy.packet import Packet  # type: ignore[import-untyped]

    p: Packet = pkt  # type: ignore[assignment]
    src, dst, protocol = "?", "?", type(p).__name__

    if p.haslayer(IP):
        ip = p[IP]  # type: ignore[index]
        src, dst = str(ip.src), str(ip.dst)
        protocol = type(ip.payload).__name__
    elif p.haslayer(IPv6):
        ip6 = p[IPv6]  # type: ignore[index]
        src, dst = str(ip6.src), str(ip6.dst)
        protocol = type(ip6.payload).__name__

    return PacketRecord(
        number=number,
        timestamp=float(p.time),  # type: ignore[attr-defined]
        src=src,
        dst=dst,
        protocol=protocol,
        length=len(p),
        summary=p.summary(),  # type: ignore[attr-defined]
    )


def get_capture_info(path: Path) -> CaptureInfo:
    """Return metadata about a capture file."""
    packets = list(read_packets(path))
    if not packets:
        return CaptureInfo(
            path=path,
            packet_count=0,
            start_time=None,
            end_time=None,
            duration_seconds=None,
        )

    start = packets[0].timestamp
    end = packets[-1].timestamp
    protocols: dict[str, int] = {}
    for pkt in packets:
        protocols[pkt.protocol] = protocols.get(pkt.protocol, 0) + 1

    return CaptureInfo(
        path=path,
        packet_count=len(packets),
        start_time=start,
        end_time=end,
        duration_seconds=end - start,
        protocols=protocols,
    )
