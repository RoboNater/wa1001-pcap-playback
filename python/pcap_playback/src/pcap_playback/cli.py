"""Click CLI for pcap-playback."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

from pcap_playback.player import replay

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
    "--rate-multiplier", "-r", default=1.0, type=float,
    help="Speed multiplier (1.0=real-time, 0=max speed).",
)
@click.option("--filter", "bpf_filter", default=None, help="BPF filter expression.")
@click.option("--count", "-n", default=None, type=int, help="Limit to first N packets.")
@click.option("--dry-run", is_flag=True, help="Preview without sending packets.")
def play(
    file: Path,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
    count: Optional[int],
    dry_run: bool,
) -> None:
    """Replay packets from a capture file to a network interface."""
    if dry_run:
        console.print("[yellow]DRY RUN[/yellow] — no packets will be sent")

    with Progress(
        SpinnerColumn(), "[progress.description]{task.description}",
        TimeElapsedColumn(), console=console,
    ) as progress:
        progress.add_task(f"Replaying {file.name}…", total=None)
        stats = replay(
            path=file,
            interface=interface,
            rate_multiplier=rate_multiplier,
            bpf_filter=bpf_filter,
            count=count,
            dry_run=dry_run,
        )

    console.print(
        f"[bold green]Done.[/bold green] "
        f"{stats.packets_sent} packets, {stats.bytes_sent} bytes, "
        f"{stats.elapsed_seconds:.2f}s elapsed"
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--interface", "-i", default=None, help="Network interface.")
@click.option("--rate-multiplier", "-r", default=1.0, type=float, help="Speed multiplier.")
@click.option("--filter", "bpf_filter", default=None, help="BPF filter expression.")
def loop(
    file: Path,
    interface: Optional[str],
    rate_multiplier: float,
    bpf_filter: Optional[str],
) -> None:
    """Replay a capture file continuously until Ctrl-C."""
    console.print(f"Looping [bold]{file.name}[/bold] — press Ctrl-C to stop")
    iteration = 0
    try:
        while True:
            iteration += 1
            console.print(f"  iteration {iteration}…")
            replay(
                path=file, interface=interface,
                rate_multiplier=rate_multiplier, bpf_filter=bpf_filter,
            )
    except KeyboardInterrupt:
        console.print(f"\n[bold]Stopped[/bold] after {iteration} iteration(s).")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--count", "-n", default=20, type=int, help="Number of packets to preview.")
def preview(file: Path, count: int) -> None:
    """Preview the first N packets without sending."""
    from scapy.utils import rdpcap  # type: ignore[import-untyped]

    packets = rdpcap(str(file))
    console.print(f"[bold]Preview:[/bold] {file.name} (first {count} packets)\n")
    for i, pkt in enumerate(packets[:count]):
        console.print(f"  [{i + 1:>4}] {pkt.summary()}")  # type: ignore[attr-defined]
