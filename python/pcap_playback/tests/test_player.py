"""Tests for pcap_playback.player."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from pcap_playback.player import PlaybackStats, load_packets, replay, rewrite_addresses


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_pkt(timestamp: float = 1_000_000.0, length: int = 64) -> MagicMock:
    pkt = MagicMock()
    pkt.time = timestamp
    pkt.__len__ = lambda self: length
    pkt.copy.return_value = pkt
    pkt.haslayer.return_value = False
    return pkt


# ---------------------------------------------------------------------------
# PlaybackStats
# ---------------------------------------------------------------------------

class TestPlaybackStats:
    def test_defaults(self) -> None:
        s = PlaybackStats()
        assert s.packets_sent == 0
        assert s.packets_skipped == 0
        assert s.bytes_sent == 0
        assert s.elapsed_seconds == 0.0


# ---------------------------------------------------------------------------
# load_packets
# ---------------------------------------------------------------------------

class TestLoadPackets:
    def test_missing_file_raises(self) -> None:
        with pytest.raises(Exception):
            load_packets(Path("/nonexistent/capture.pcap"))

    def test_calls_rdpcap_without_filter(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts) as mock_rdpcap:
            result = load_packets(Path("fake.pcap"))
        mock_rdpcap.assert_called_once_with(str(Path("fake.pcap")))
        assert result == pkts

    def test_calls_sniff_with_filter(self) -> None:
        pkts = [_mock_pkt()]
        with patch("pcap_playback.player.rdpcap"):
            with patch("scapy.all.sniff", return_value=pkts) as mock_sniff:
                result = load_packets(Path("fake.pcap"), bpf_filter="udp")
        mock_sniff.assert_called_once_with(offline=str(Path("fake.pcap")), filter="udp")
        assert result == pkts


# ---------------------------------------------------------------------------
# rewrite_addresses
# ---------------------------------------------------------------------------

class TestRewriteAddresses:
    def test_no_rewrite_returns_same_object(self) -> None:
        pkt = _mock_pkt()
        result = rewrite_addresses(pkt, None, None)
        assert result is pkt

    def test_rewrite_applied_to_ip_layer(self) -> None:
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP, UDP  # type: ignore[import-untyped]
        from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

        original = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / UDP() / b"data"
        result = rewrite_addresses(original, "10.0.0.1", "10.0.0.2")

        assert result is not original  # must be a copy
        assert result[IP].src == "10.0.0.1"  # type: ignore[index]
        assert result[IP].dst == "10.0.0.2"  # type: ignore[index]
        assert original[IP].src == "1.2.3.4"  # original untouched

    def test_partial_rewrite_src_only(self) -> None:
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP  # type: ignore[import-untyped]
        from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

        original = Ether() / IP(src="1.2.3.4", dst="5.6.7.8")
        result = rewrite_addresses(original, "10.0.0.1", None)

        assert result[IP].src == "10.0.0.1"  # type: ignore[index]
        assert result[IP].dst == "5.6.7.8"  # type: ignore[index]


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_missing_file_raises(self) -> None:
        with pytest.raises(Exception):
            replay(Path("/nonexistent/file.pcap"))

    def test_dry_run_does_not_call_sendp(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.sendp") as mock_send:
                stats = replay(Path("fake.pcap"), dry_run=True)
        mock_send.assert_not_called()
        assert stats.packets_sent == 2

    def test_dry_run_counts_bytes(self) -> None:
        pkts = [_mock_pkt(length=100), _mock_pkt(length=200)]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            stats = replay(Path("fake.pcap"), dry_run=True)
        assert stats.bytes_sent == 300

    def test_count_limits_packets(self) -> None:
        pkts = [_mock_pkt()] * 10
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            stats = replay(Path("fake.pcap"), dry_run=True, count=4)
        assert stats.packets_sent == 4

    def test_on_packet_callback_receives_all_packets(self) -> None:
        pkts = [_mock_pkt()] * 3
        seen: list[int] = []
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            replay(Path("fake.pcap"), dry_run=True, on_packet=lambda n, _: seen.append(n))
        assert seen == [1, 2, 3]

    def test_sendp_called_per_packet_when_not_dry_run(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.sendp") as mock_send:
                stats = replay(Path("fake.pcap"), interface="lo", dry_run=False)
        assert mock_send.call_count == 2
        assert stats.packets_sent == 2
        assert stats.packets_skipped == 0

    def test_sendp_failure_increments_skipped(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.sendp", side_effect=OSError("no interface")):
                stats = replay(Path("fake.pcap"), interface="eth0", dry_run=False)
        assert stats.packets_sent == 0
        assert stats.packets_skipped == 2

    def test_rate_multiplier_zero_skips_sleep(self) -> None:
        t = 1_000_000.0
        pkts = [_mock_pkt(timestamp=t), _mock_pkt(timestamp=t + 1.0)]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.time") as mock_time:
                mock_time.monotonic.side_effect = [0.0, 0.1]
                replay(Path("fake.pcap"), dry_run=True, rate_multiplier=0)
        # time.sleep should never have been called
        mock_time.sleep.assert_not_called()

    def test_elapsed_seconds_recorded(self) -> None:
        pkts = [_mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            stats = replay(Path("fake.pcap"), dry_run=True)
        assert stats.elapsed_seconds >= 0.0


# ---------------------------------------------------------------------------
# Integration tests (require scapy + real pcap file)
# ---------------------------------------------------------------------------

class TestReplayIntegration:
    def test_dry_run_full_file(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats = replay(sample_pcap, dry_run=True)
        assert stats.packets_sent == 2
        assert stats.bytes_sent > 0
        assert stats.packets_skipped == 0

    def test_count_limits_real_file(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats = replay(sample_pcap, dry_run=True, count=1)
        assert stats.packets_sent == 1

    def test_max_speed_replay(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats = replay(sample_pcap, dry_run=True, rate_multiplier=0)
        assert stats.packets_sent == 2

    def test_preview_via_load_packets(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        pkts = load_packets(sample_pcap)
        assert len(pkts) == 2
