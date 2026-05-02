"""Click CLI for pcap-reader."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from pcap_reader.reader import get_capture_info, read_packets

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def cli(verbose: bool) -> None:
    """Inspect and analyze PCAP/PCAPNG network capture files."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def info(file: Path) -> None:
    """Print metadata about a capture file."""
    cap = get_capture_info(file)
    console.print(f"[bold]File:[/bold]     {cap.path}")
    console.print(f"[bold]Packets:[/bold]  {cap.packet_count}")
    console.print(f"[bold]Duration:[/bold] {cap.duration_str}")
    if cap.protocols:
        console.print("[bold]Protocols:[/bold]")
        for proto, cnt in sorted(cap.protocols.items(), key=lambda x: -x[1]):
            console.print(f"  {proto:<20} {cnt}")


@cli.command(name="list")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--filter", "bpf_filter", default=None, help="BPF filter expression.")
@click.option("--count", "-n", default=None, type=int, help="Limit packet count.")
@click.option(
    "--format", "fmt", default="text",
    type=click.Choice(["text", "json", "csv"]),
    help="Output format.",
)
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Output file.")
def list_packets(
    file: Path,
    bpf_filter: Optional[str],
    count: Optional[int],
    fmt: str,
    output: Optional[Path],
) -> None:
    """List packets in a capture file."""
    packets = list(read_packets(file, bpf_filter=bpf_filter, count=count))

    if fmt == "json":
        data = [
            {
                "#": p.number, "time": p.timestamp, "src": p.src, "dst": p.dst,
                "protocol": p.protocol, "len": p.length, "info": p.summary,
            }
            for p in packets
        ]
        _write_output(json.dumps(data, indent=2), output)

    elif fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["#", "timestamp", "src", "dst", "protocol", "len", "info"])
        for p in packets:
            writer.writerow([p.number, p.timestamp, p.src, p.dst, p.protocol, p.length, p.summary])
        _write_output(buf.getvalue(), output)

    else:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=6)
        table.add_column("Timestamp", width=24)
        table.add_column("Src", width=20)
        table.add_column("Dst", width=20)
        table.add_column("Proto", width=10)
        table.add_column("Len", width=6)
        table.add_column("Info")
        for p in packets:
            ts = datetime.fromtimestamp(p.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
            table.add_row(str(p.number), ts, p.src, p.dst, p.protocol, str(p.length), p.summary)
        if output:
            with open(output, "w") as f:
                Console(file=f).print(table)
        else:
            console.print(table)


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--filter", "bpf_filter", default=None, help="BPF filter expression.")
def summary(file: Path, bpf_filter: Optional[str]) -> None:
    """Print a protocol summary for a capture file."""
    cap = get_capture_info(file)
    console.print(f"[bold]{file.name}[/bold] — {cap.packet_count} packets, {cap.duration_str}")
    table = Table("Protocol", "Packets", "%", show_header=True, header_style="bold cyan")
    total = cap.packet_count or 1
    for proto, cnt in sorted(cap.protocols.items(), key=lambda x: -x[1]):
        table.add_row(proto, str(cnt), f"{100 * cnt / total:.1f}%")
    console.print(table)


def _write_output(text: str, path: Optional[Path]) -> None:
    if path:
        path.write_text(text)
    else:
        click.echo(text)
