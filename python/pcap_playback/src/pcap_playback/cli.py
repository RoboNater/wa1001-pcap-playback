"""Click CLI for pcap-playback."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table

from pcap_playback.player import PlaybackStats, load_packets, replay

console = Console()

_MODE_HELP = (
    "Replay mode. 'socket' (default): sends UDP packets and TCP streams via "
    "normal OS sockets — no root required. 'raw': full Layer-2 replay via "
    "scapy sendp — requires root or CAP_NET_RAW."
)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def cli(verbose: bool) -> None:
    """Replay PCAP/PCAPNG network capture files to a live interface."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--mode", "-m", default="socket", type=click.Choice(["socket", "raw"]),
              show_default=True, help=_MODE_HELP)
@click.option("--interface", "-i", default=None,
              help="Network interface for raw mode (e.g. eth0). Ignored in socket mode.")
@click.option("--rate-multiplier", "-r", default=1.0, type=float, show_default=True,
              help="Speed: 1.0=real-time, 2.0=double speed, 0=max speed.")
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR",
              help="BPF filter — only replay matching packets.")
@click.option("--count", "-n", default=None, type=int, help="Stop after N packets.")
@click.option("--src-rewrite", default=None, metavar="IP",
              help="Rewrite source IP (raw mode only).")
@click.option("--dst-rewrite", default=None, metavar="IP",
              help="Rewrite destination IP.")
@click.option("--dry-run", is_flag=True,
              help="Count packets without transmitting anything.")
def play(
    file: Path,
    mode: str,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
    count: Optional[int],
    src_rewrite: Optional[str],
    dst_rewrite: Optional[str],
    dry_run: bool,
) -> None:
    """Replay packets from a capture file."""
    if dry_run:
        console.print("[yellow]DRY RUN[/yellow] — no packets will be transmitted")

    if mode == "raw" and not dry_run and interface is None:
        console.print(
            "[yellow]Warning:[/yellow] no --interface given; "
            "scapy will use the default route interface."
        )

    try:
        packets = load_packets(file, bpf_filter)
        total = min(len(packets), count) if count else len(packets)

        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Replaying [bold]{file.name}[/bold]", total=total)

            def _on_packet(n: int, _: object) -> None:
                progress.update(task, completed=n)

            stats = replay(
                path=file,
                mode=mode,
                interface=interface,
                rate_multiplier=rate_multiplier,
                bpf_filter=bpf_filter,
                count=count,
                dry_run=dry_run,
                src_rewrite=src_rewrite,
                dst_rewrite=dst_rewrite,
                on_packet=_on_packet,
            )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    console.print(_format_stats(stats, mode))


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--mode", "-m", default="socket", type=click.Choice(["socket", "raw"]),
              show_default=True, help=_MODE_HELP)
@click.option("--interface", "-i", default=None, help="Network interface (raw mode only).")
@click.option("--rate-multiplier", "-r", default=1.0, type=float, show_default=True,
              help="Speed multiplier.")
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR", help="BPF filter.")
@click.option("--src-rewrite", default=None, metavar="IP", help="Rewrite source IP (raw mode).")
@click.option("--dst-rewrite", default=None, metavar="IP", help="Rewrite destination IP.")
def loop(
    file: Path,
    mode: str,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
    src_rewrite: Optional[str],
    dst_rewrite: Optional[str],
) -> None:
    """Replay a capture file continuously until Ctrl-C."""
    console.print(f"Looping [bold]{file.name}[/bold] in {mode} mode — press Ctrl-C to stop")
    iteration = 0
    try:
        while True:
            iteration += 1
            stats = replay(
                path=file,
                mode=mode,
                interface=interface,
                rate_multiplier=rate_multiplier,
                bpf_filter=bpf_filter,
                src_rewrite=src_rewrite,
                dst_rewrite=dst_rewrite,
            )
            console.print(f"  [{iteration}] {_format_stats(stats, mode)}")
    except KeyboardInterrupt:
        console.print(f"\n[bold]Stopped[/bold] after {iteration} iteration(s).")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--count", "-n", default=20, show_default=True, type=int,
              help="Number of packets to show.")
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR", help="BPF filter.")
def preview(file: Path, count: int, bpf_filter: Optional[str]) -> None:
    """Show a table of the first N packets without transmitting anything."""
    try:
        packets = load_packets(file, bpf_filter)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    shown = packets[:count]
    table = Table(show_header=True, header_style="bold cyan", title=f"{file.name} — preview")
    table.add_column("#", style="dim", width=6)
    table.add_column("Timestamp", width=24)
    table.add_column("Src", width=20)
    table.add_column("Dst", width=20)
    table.add_column("Proto", width=10)
    table.add_column("Len", width=6, justify="right")
    table.add_column("Summary")

    for i, pkt in enumerate(shown):
        ts = datetime.fromtimestamp(
            float(pkt.time)  # type: ignore[attr-defined]
        ).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
        src, dst, proto = _packet_fields(pkt)
        table.add_row(
            str(i + 1), ts, src, dst, proto,
            str(len(pkt)),  # type: ignore[arg-type]
            pkt.summary(),  # type: ignore[attr-defined]
        )

    console.print(table)
    console.print(
        f"[dim]Showing {len(shown)} of {len(packets)} packet(s)"
        + (f" (filter: {bpf_filter})" if bpf_filter else "")
        + "[/dim]"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_stats(stats: PlaybackStats, mode: str) -> str:
    skipped = f", {stats.packets_skipped} skipped" if stats.packets_skipped else ""
    elapsed = f"{stats.elapsed_seconds:.3f}s"
    kb = f"{stats.bytes_sent:,} bytes"

    if mode == "socket":
        parts = []
        if stats.packets_sent:
            parts.append(f"{stats.packets_sent} UDP packet(s)")
        if stats.tcp_flows_sent:
            parts.append(f"{stats.tcp_flows_sent} TCP flow(s)")
        sent = ", ".join(parts) if parts else "0 packets"
        return f"[bold green]Done.[/bold green] {sent}{skipped}, {kb}, {elapsed}"
    else:
        return (
            f"[bold green]Done.[/bold green] "
            f"{stats.packets_sent} packet(s){skipped}, {kb}, {elapsed}"
        )


def _packet_fields(pkt: object) -> tuple[str, str, str]:
    try:
        from scapy.layers.inet import IP  # type: ignore[import-untyped]
        from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
        from scapy.packet import Packet  # type: ignore[import-untyped]

        p: Packet = pkt  # type: ignore[assignment]
        if p.haslayer(IP):
            ip = p[IP]
            return str(ip.src), str(ip.dst), type(ip.payload).__name__
        if p.haslayer(IPv6):
            ip6 = p[IPv6]
            return str(ip6.src), str(ip6.dst), type(ip6.payload).__name__
    except Exception:
        pass
    return "?", "?", type(pkt).__name__
