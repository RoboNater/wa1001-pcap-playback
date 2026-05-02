"""Tests for pcap_playback.player."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pcap_playback.player import PlaybackStats, replay


class TestPlaybackStats:
    def test_defaults(self) -> None:
        s = PlaybackStats()
        assert s.packets_sent == 0
        assert s.packets_skipped == 0
        assert s.bytes_sent == 0


class TestReplay:
    def test_missing_file_raises(self) -> None:
        with pytest.raises(Exception):
            replay(Path("/nonexistent/file.pcap"))

    def test_dry_run_counts_without_sending(self) -> None:
        mock_pkt = MagicMock()
        mock_pkt.time = 1000.0
        mock_pkt.__len__ = lambda self: 64

        with patch("pcap_playback.player.rdpcap", return_value=[mock_pkt, mock_pkt]):
            with patch("pcap_playback.player.sendp") as mock_send:
                stats = replay(Path("fake.pcap"), dry_run=True)

        mock_send.assert_not_called()
        assert stats.packets_sent == 2
        assert stats.bytes_sent == 128

    def test_count_limits_packets(self) -> None:
        mock_pkt = MagicMock()
        mock_pkt.time = 1000.0
        mock_pkt.__len__ = lambda self: 64

        with patch("pcap_playback.player.rdpcap", return_value=[mock_pkt] * 10):
            stats = replay(Path("fake.pcap"), dry_run=True, count=3)

        assert stats.packets_sent == 3

    def test_on_packet_callback(self) -> None:
        mock_pkt = MagicMock()
        mock_pkt.time = 1000.0
        mock_pkt.__len__ = lambda self: 64
        seen: list[int] = []

        with patch("pcap_playback.player.rdpcap", return_value=[mock_pkt, mock_pkt]):
            replay(Path("fake.pcap"), dry_run=True, on_packet=lambda n, _: seen.append(n))

        assert seen == [1, 2]
