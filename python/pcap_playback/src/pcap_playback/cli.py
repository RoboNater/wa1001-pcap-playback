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

from pcap_playback.player import load_packets, replay

console = Console()


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
@click.option("--interface", "-i", default=None, help="Network interface (e.g. eth0).")
@click.option(
    "--rate-multiplier", "-r", default=1.0, type=float, show_default=True,
    help="Speed multiplier: 1.0=real-time, 2.0=double speed, 0=max speed.",
)
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR", help="BPF filter expression.")
@click.option("--count", "-n", default=None, type=int, help="Stop after N packets.")
@click.option("--src-rewrite", default=None, metavar="IP", help="Rewrite source IP address.")
@click.option("--dst-rewrite", default=None, metavar="IP", help="Rewrite destination IP address.")
@click.option("--dry-run", is_flag=True, help="Count packets without transmitting.")
def play(
    file: Path,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
    count: Optional[int],
    src_rewrite: Optional[str],
    dst_rewrite: Optional[str],
    dry_run: bool,
) -> None:
    """Replay packets from a capture file to a network interface."""
    if not dry_run and interface is None:
        console.print(
            "[yellow]Warning:[/yellow] no --interface specified; "
            "scapy will use the default route interface."
        )
    if dry_run:
        console.print("[yellow]DRY RUN[/yellow] — no packets will be transmitted")

    try:
        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            total_pkts = len(load_packets(file, bpf_filter))
            if count is not None:
                total_pkts = min(total_pkts, count)
            task = progress.add_task(f"Replaying [bold]{file.name}[/bold]", total=total_pkts)

            def _on_packet(n: int, _: object) -> None:
                progress.update(task, completed=n)

            stats = replay(
                path=file,
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

    console.print(
        f"[bold green]Done.[/bold green] "
        f"{stats.packets_sent} packet(s) sent, "
        f"{stats.bytes_sent:,} bytes, "
        f"{stats.elapsed_seconds:.3f}s elapsed"
        + (f" ({stats.packets_skipped} skipped)" if stats.packets_skipped else "")
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--interface", "-i", default=None, help="Network interface.")
@click.option(
    "--rate-multiplier", "-r", default=1.0, type=float, show_default=True,
    help="Speed multiplier.",
)
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR", help="BPF filter expression.")
@click.option("--src-rewrite", default=None, metavar="IP", help="Rewrite source IP address.")
@click.option("--dst-rewrite", default=None, metavar="IP", help="Rewrite destination IP address.")
def loop(
    file: Path,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
    src_rewrite: Optional[str],
    dst_rewrite: Optional[str],
) -> None:
    """Replay a capture file continuously until Ctrl-C."""
    console.print(f"Looping [bold]{file.name}[/bold] — press Ctrl-C to stop")
    iteration = 0
    try:
        while True:
            iteration += 1
            stats = replay(
                path=file,
                interface=interface,
                rate_multiplier=rate_multiplier,
                bpf_filter=bpf_filter,
                src_rewrite=src_rewrite,
                dst_rewrite=dst_rewrite,
            )
            console.print(
                f"  [{iteration}] {stats.packets_sent} packets, "
                f"{stats.bytes_sent:,} bytes, {stats.elapsed_seconds:.3f}s"
            )
    except KeyboardInterrupt:
        console.print(f"\n[bold]Stopped[/bold] after {iteration} iteration(s).")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--count", "-n", default=20, show_default=True, type=int,
              help="Number of packets to preview.")
@click.option("--filter", "bpf_filter", default=None, metavar="EXPR", help="BPF filter expression.")
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
        ts = datetime.fromtimestamp(float(pkt.time)).strftime(  # type: ignore[attr-defined]
            "%Y-%m-%d %H:%M:%S.%f"
        )[:23]
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


def _packet_fields(pkt: object) -> tuple[str, str, str]:
    """Extract (src, dst, protocol) from a scapy packet."""
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
