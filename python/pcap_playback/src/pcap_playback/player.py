"""Core replay logic for pcap-playback."""

from __future__ import annotations

import logging
import socket as _socket
import time
from collections import defaultdict
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
    packets_sent: int = 0       # UDP packets (socket mode) or all packets (raw mode)
    packets_skipped: int = 0
    bytes_sent: int = 0
    elapsed_seconds: float = 0.0
    tcp_flows_sent: int = 0     # TCP streams sent (socket mode only)


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
        del ip.chksum
        if hasattr(ip.payload, "chksum"):
            del ip.payload.chksum
    return p


# ---------------------------------------------------------------------------
# Shared timing helper
# ---------------------------------------------------------------------------

def _sleep_gap(pkt_time: float, prev_time: float | None, rate_multiplier: float) -> None:
    if prev_time is not None and rate_multiplier > 0:
        gap = (pkt_time - prev_time) / rate_multiplier
        if gap > 0:
            time.sleep(gap)


# ---------------------------------------------------------------------------
# Socket mode (no root required)
# ---------------------------------------------------------------------------

def collect_tcp_flows(
    packets: list[object], count: int | None = None,
) -> dict[tuple[str, int, str, int], bytes]:
    """
    Pre-scan packets and return the reassembled payload for each TCP flow.

    Flow key is (src_ip, src_port, dst_ip, dst_port). Segments are concatenated
    in packet order, which is sufficient for captures without retransmissions.
    """
    from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]

    buffers: dict[tuple[str, int, str, int], list[bytes]] = defaultdict(list)
    for i, pkt in enumerate(packets):
        if count is not None and i >= count:
            break
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):  # type: ignore[attr-defined]
                continue
            ip, tcp = pkt[IP], pkt[TCP]  # type: ignore[index]
            payload = bytes(tcp.payload)
            if payload:
                key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
                buffers[key].append(payload)
        except Exception:
            pass
    return {k: b"".join(chunks) for k, chunks in buffers.items()}


def _replay_socket(
    packets: list[object],
    rate_multiplier: float,
    count: int | None,
    dst_rewrite: str | None,
    dry_run: bool,
    on_packet: Callable[[int, object], None] | None,
    stats: PlaybackStats,
) -> None:
    """
    Send using OS sockets — no root required.

    UDP packets are sent individually, preserving inter-packet timing.
    TCP flows are reassembled per (src, sport, dst, dport) tuple and sent
    as a single connection at the timestamp of the flow's first data packet.
    Non-IP and non-UDP/TCP packets are silently skipped.
    """
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]

    tcp_flows = collect_tcp_flows(packets, count)
    sent_tcp_flows: set[tuple[str, int, str, int]] = set()
    skipped_proto = 0
    prev_time: float | None = None

    for i, pkt in enumerate(packets):
        if count is not None and i >= count:
            break

        pkt_time = float(pkt.time)  # type: ignore[attr-defined]
        _sleep_gap(pkt_time, prev_time, rate_multiplier)
        prev_time = pkt_time

        if on_packet:
            on_packet(i + 1, pkt)

        try:
            if not pkt.haslayer(IP):  # type: ignore[attr-defined]
                skipped_proto += 1
                continue

            ip = pkt[IP]  # type: ignore[index]
            effective_dst = dst_rewrite or str(ip.dst)

            if pkt.haslayer(UDP):  # type: ignore[attr-defined]
                payload = bytes(pkt[UDP].payload)  # type: ignore[index]
                if not payload:
                    skipped_proto += 1
                    continue
                if not dry_run:
                    with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
                        sock.sendto(payload, (effective_dst, int(pkt[UDP].dport)))  # type: ignore[index]
                stats.packets_sent += 1
                stats.bytes_sent += len(payload)

            elif pkt.haslayer(TCP):  # type: ignore[attr-defined]
                tcp = pkt[TCP]  # type: ignore[index]
                flow_key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
                if flow_key in sent_tcp_flows or flow_key not in tcp_flows:
                    continue  # already sent, or this flow has no payload
                stream = tcp_flows[flow_key]
                sent_tcp_flows.add(flow_key)
                if not dry_run:
                    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sock:
                        sock.settimeout(30.0)
                        sock.connect((effective_dst, int(tcp.dport)))
                        sock.sendall(stream)
                stats.tcp_flows_sent += 1
                stats.bytes_sent += len(stream)

            else:
                skipped_proto += 1

        except Exception as exc:
            logger.warning("Send failed for packet %d: %s", i + 1, exc)
            stats.packets_skipped += 1

    if skipped_proto:
        logger.debug("Skipped %d non-UDP/TCP or empty packet(s).", skipped_proto)


# ---------------------------------------------------------------------------
# Raw mode (Layer 2, requires root)
# ---------------------------------------------------------------------------

def _replay_raw(
    packets: list[object],
    interface: str | None,
    rate_multiplier: float,
    count: int | None,
    dry_run: bool,
    src_rewrite: str | None,
    dst_rewrite: str | None,
    on_packet: Callable[[int, object], None] | None,
    stats: PlaybackStats,
) -> None:
    """Full Layer-2 replay via scapy sendp. Requires root / CAP_NET_RAW."""
    prev_time: float | None = None

    for i, raw_pkt in enumerate(packets):
        if count is not None and i >= count:
            break

        pkt_time = float(raw_pkt.time)  # type: ignore[attr-defined]
        _sleep_gap(pkt_time, prev_time, rate_multiplier)
        prev_time = pkt_time

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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def replay(
    path: Path,
    mode: str = "socket",
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

    mode="socket" (default)
        No root required. Sends UDP payload per-packet and reassembles TCP
        streams per flow using normal OS sockets. The OS assigns the source
        IP; use --dst-rewrite to redirect traffic. src_rewrite and interface
        are ignored. Non-UDP/TCP packets are skipped.

    mode="raw"
        Full Layer-2 replay via scapy sendp. Preserves every header exactly.
        Requires root or CAP_NET_RAW. dry_run=True bypasses sending.

    rate_multiplier=0  → maximum throughput (no inter-packet sleep).
    on_packet          → called as on_packet(packet_number, packet) each iteration.
    """
    _require_scapy()
    packets = load_packets(path, bpf_filter)
    stats = PlaybackStats()
    start_wall = time.monotonic()

    if mode == "socket":
        if src_rewrite:
            logger.warning("--src-rewrite is ignored in socket mode (the OS assigns the source IP).")
        if interface:
            logger.warning("--interface is ignored in socket mode (the OS handles routing).")
        _replay_socket(packets, rate_multiplier, count, dst_rewrite, dry_run, on_packet, stats)
    elif mode == "raw":
        _replay_raw(packets, interface, rate_multiplier, count, dry_run,
                    src_rewrite, dst_rewrite, on_packet, stats)
    else:
        raise ValueError(f"Unknown mode {mode!r}. Choose 'socket' or 'raw'.")

    stats.elapsed_seconds = time.monotonic() - start_wall
    return stats
