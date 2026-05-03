"""Shared test fixtures for pcap_playback tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """
    Two-packet Ethernet/IPv4/UDP capture file written to a temp directory.
    Requires scapy (installed as a project dependency).
    """
    scapy_utils = pytest.importorskip("scapy.utils")
    from scapy.layers.inet import IP, UDP  # type: ignore[import-untyped]
    from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

    p1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / b"QUERY"
    p2 = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=53, dport=12345) / b"RESPONSE"
    # Explicit timestamps so timing tests are deterministic
    p1.time = 1_000_000.000
    p2.time = 1_000_000.010  # 10 ms later

    out = tmp_path_factory.mktemp("fixtures") / "sample.pcap"
    scapy_utils.wrpcap(str(out), [p1, p2])
    return out
