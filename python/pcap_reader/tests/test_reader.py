"""Tests for pcap_reader.reader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pcap_reader.reader import CaptureInfo, PacketRecord


class TestPacketRecord:
    def test_fields(self) -> None:
        r = PacketRecord(
            number=1, timestamp=1000.0, src="1.2.3.4", dst="5.6.7.8",
            protocol="TCP", length=64, summary="SYN",
        )
        assert r.number == 1
        assert r.src == "1.2.3.4"
        assert r.protocol == "TCP"
        assert r.length == 64


class TestCaptureInfo:
    def test_duration_str_when_none(self) -> None:
        info = CaptureInfo(
            path=Path("x.pcap"), packet_count=0,
            start_time=None, end_time=None, duration_seconds=None,
        )
        assert info.duration_str == "unknown"

    def test_duration_str(self) -> None:
        info = CaptureInfo(
            path=Path("x.pcap"), packet_count=10,
            start_time=0.0, end_time=5.5, duration_seconds=5.5,
        )
        assert info.duration_str == "5.500s"


class TestReadPackets:
    def test_missing_file_raises(self) -> None:
        from pcap_reader.reader import read_packets
        with pytest.raises(Exception):
            list(read_packets(Path("/nonexistent/capture.pcap")))

    def test_count_limits_output(self) -> None:
        mock_pkt = MagicMock()
        mock_pkt.time = 1000.0
        mock_pkt.__len__ = lambda self: 64
        mock_pkt.summary.return_value = "Mock packet"
        mock_pkt.haslayer.return_value = False

        with patch("pcap_reader.reader.rdpcap", return_value=[mock_pkt] * 10):
            from pcap_reader.reader import read_packets
            results = list(read_packets(Path("fake.pcap"), count=3))

        assert len(results) == 3
