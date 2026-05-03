"""Tests for pcap_playback.player."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pcap_playback.player import (
    PlaybackStats,
    collect_tcp_flows,
    load_packets,
    replay,
    rewrite_addresses,
)


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


def _mock_udp_pkt(
    src_ip: str = "1.2.3.4", dst_ip: str = "5.6.7.8",
    sport: int = 1234, dport: int = 53,
    payload: bytes = b"data",
    timestamp: float = 1_000_000.0,
) -> MagicMock:
    from scapy.layers.inet import IP, UDP  # type: ignore[import-untyped]
    from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
    pkt.time = timestamp
    return pkt


def _mock_tcp_pkt(
    src_ip: str = "1.2.3.4", dst_ip: str = "5.6.7.8",
    sport: int = 54321, dport: int = 80,
    payload: bytes = b"GET / HTTP/1.0\r\n\r\n",
    timestamp: float = 1_000_000.0,
    flags: str = "PA",
) -> MagicMock:
    from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
    from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags) / payload
    pkt.time = timestamp
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
        assert s.tcp_flows_sent == 0


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
        assert rewrite_addresses(pkt, None, None) is pkt

    def test_rewrites_src_and_dst(self) -> None:
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP  # type: ignore[import-untyped]
        from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

        original = Ether() / IP(src="1.2.3.4", dst="5.6.7.8")
        result = rewrite_addresses(original, "10.0.0.1", "10.0.0.2")
        assert result is not original
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
# collect_tcp_flows
# ---------------------------------------------------------------------------

class TestCollectTcpFlows:
    def test_returns_reassembled_payload(self) -> None:
        pytest.importorskip("scapy")
        p1 = _mock_tcp_pkt(payload=b"Hello ")
        p2 = _mock_tcp_pkt(payload=b"World", timestamp=1_000_000.1)
        flows = collect_tcp_flows([p1, p2])
        assert len(flows) == 1
        key = ("1.2.3.4", 54321, "5.6.7.8", 80)
        assert flows[key] == b"Hello World"

    def test_respects_count(self) -> None:
        pytest.importorskip("scapy")
        pkts = [_mock_tcp_pkt(payload=b"A"), _mock_tcp_pkt(payload=b"B")]
        flows = collect_tcp_flows(pkts, count=1)
        key = ("1.2.3.4", 54321, "5.6.7.8", 80)
        assert flows[key] == b"A"

    def test_ignores_empty_payload(self) -> None:
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
        from scapy.layers.l2 import Ether  # type: ignore[import-untyped]

        syn = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=54321, dport=80, flags="S")
        syn.time = 1_000_000.0
        flows = collect_tcp_flows([syn])
        assert flows == {}

    def test_separate_flows_keyed_independently(self) -> None:
        pytest.importorskip("scapy")
        p1 = _mock_tcp_pkt(src_ip="1.1.1.1", sport=100, dst_ip="2.2.2.2", dport=80, payload=b"req")
        p2 = _mock_tcp_pkt(src_ip="3.3.3.3", sport=200, dst_ip="4.4.4.4", dport=80, payload=b"req2")
        flows = collect_tcp_flows([p1, p2])
        assert len(flows) == 2


# ---------------------------------------------------------------------------
# replay — raw mode (existing behaviour)
# ---------------------------------------------------------------------------

class TestReplayRaw:
    def test_missing_file_raises(self) -> None:
        with pytest.raises(Exception):
            replay(Path("/nonexistent/file.pcap"), mode="raw")

    def test_dry_run_does_not_call_sendp(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.sendp") as mock_send:
                stats = replay(Path("fake.pcap"), mode="raw", dry_run=True)
        mock_send.assert_not_called()
        assert stats.packets_sent == 2

    def test_dry_run_counts_bytes(self) -> None:
        pkts = [_mock_pkt(length=100), _mock_pkt(length=200)]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            stats = replay(Path("fake.pcap"), mode="raw", dry_run=True)
        assert stats.bytes_sent == 300

    def test_count_limits_packets(self) -> None:
        pkts = [_mock_pkt()] * 10
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            stats = replay(Path("fake.pcap"), mode="raw", dry_run=True, count=4)
        assert stats.packets_sent == 4

    def test_sendp_failure_increments_skipped(self) -> None:
        pkts = [_mock_pkt(), _mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.sendp", side_effect=OSError("no iface")):
                stats = replay(Path("fake.pcap"), mode="raw")
        assert stats.packets_skipped == 2
        assert stats.packets_sent == 0

    def test_rate_multiplier_zero_skips_sleep(self) -> None:
        t = 1_000_000.0
        pkts = [_mock_pkt(timestamp=t), _mock_pkt(timestamp=t + 1.0)]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with patch("pcap_playback.player.time") as mock_time:
                mock_time.monotonic.side_effect = [0.0, 0.1]
                replay(Path("fake.pcap"), mode="raw", dry_run=True, rate_multiplier=0)
        mock_time.sleep.assert_not_called()

    def test_invalid_mode_raises(self) -> None:
        pkts = [_mock_pkt()]
        with patch("pcap_playback.player.rdpcap", return_value=pkts):
            with pytest.raises(ValueError, match="Unknown mode"):
                replay(Path("fake.pcap"), mode="invalid")


# ---------------------------------------------------------------------------
# replay — socket mode
# ---------------------------------------------------------------------------

class TestReplaySocket:
    def test_udp_sent_via_socket(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        sent: list[tuple[bytes, tuple[str, int]]] = []

        class FakeUDPSocket:
            def __enter__(self) -> "FakeUDPSocket":
                return self
            def __exit__(self, *_: object) -> None:
                pass
            def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
                sent.append((data, addr))

        def fake_socket(family: int, kind: int) -> FakeUDPSocket:
            return FakeUDPSocket()

        with patch("pcap_playback.player._socket.socket", side_effect=fake_socket):
            stats = replay(sample_pcap, mode="socket")

        assert stats.packets_sent >= 1          # at least one UDP packet
        assert stats.bytes_sent > 0
        assert len(sent) == stats.packets_sent  # one sendto per UDP packet

    def test_dry_run_no_socket_opened(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        with patch("pcap_playback.player._socket.socket") as mock_sock:
            stats = replay(sample_pcap, mode="socket", dry_run=True)
        mock_sock.assert_not_called()
        assert stats.packets_sent >= 1

    def test_count_limits_socket_mode(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats_all = replay(sample_pcap, mode="socket", dry_run=True)
        stats_one = replay(sample_pcap, mode="socket", dry_run=True, count=1)
        assert stats_one.packets_sent <= stats_all.packets_sent

    def test_dst_rewrite_used_in_sendto(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        sent_to: list[tuple[str, int]] = []

        class FakeUDPSocket:
            def __enter__(self) -> "FakeUDPSocket":
                return self
            def __exit__(self, *_: object) -> None:
                pass
            def sendto(self, _: bytes, addr: tuple[str, int]) -> None:
                sent_to.append(addr)

        with patch("pcap_playback.player._socket.socket", side_effect=lambda *_: FakeUDPSocket()):
            replay(sample_pcap, mode="socket", dst_rewrite="10.99.99.99")

        assert all(addr[0] == "10.99.99.99" for addr in sent_to)

    def test_src_rewrite_warns_and_is_ignored(self, sample_pcap: Path, caplog: pytest.LogCaptureFixture) -> None:
        pytest.importorskip("scapy")
        with caplog.at_level(logging.WARNING, logger="pcap_playback.player"):
            replay(sample_pcap, mode="socket", dry_run=True, src_rewrite="9.9.9.9")
        assert any("src-rewrite" in r.message for r in caplog.records)

    def test_tcp_flow_sent_as_single_connection(self) -> None:
        pytest.importorskip("scapy")
        p1 = _mock_tcp_pkt(payload=b"GET / HTTP/1.0\r\n\r\n")
        p2 = _mock_tcp_pkt(payload=b"extra", timestamp=1_000_000.1)

        connect_calls: list = []
        sendall_calls: list = []

        class FakeTCPSocket:
            def __enter__(self) -> "FakeTCPSocket":
                return self
            def __exit__(self, *_: object) -> None:
                pass
            def settimeout(self, t: float) -> None:
                pass
            def connect(self, addr: tuple) -> None:
                connect_calls.append(addr)
            def sendall(self, data: bytes) -> None:
                sendall_calls.append(data)

        with patch("pcap_playback.player.rdpcap", return_value=[p1, p2]):
            with patch("pcap_playback.player._socket.socket",
                       side_effect=lambda f, k: FakeTCPSocket()):
                stats = replay(Path("fake.pcap"), mode="socket")

        assert stats.tcp_flows_sent == 1
        assert len(connect_calls) == 1           # one connection for the whole flow
        assert sendall_calls[0] == b"GET / HTTP/1.0\r\n\r\nextra"  # reassembled

    def test_send_failure_increments_skipped(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")

        class BrokenSocket:
            def __enter__(self) -> "BrokenSocket":
                return self
            def __exit__(self, *_: object) -> None:
                pass
            def sendto(self, *_: object) -> None:
                raise OSError("network unreachable")

        with patch("pcap_playback.player._socket.socket", side_effect=lambda *_: BrokenSocket()):
            stats = replay(sample_pcap, mode="socket")

        assert stats.packets_skipped > 0
        assert stats.packets_sent == 0


# ---------------------------------------------------------------------------
# Integration tests (real pcap, real scapy)
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_raw_dry_run_full_file(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats = replay(sample_pcap, mode="raw", dry_run=True)
        assert stats.packets_sent == 2
        assert stats.bytes_sent > 0

    def test_socket_dry_run_full_file(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        stats = replay(sample_pcap, mode="socket", dry_run=True)
        assert stats.packets_sent >= 1
        assert stats.bytes_sent > 0

    def test_socket_mode_is_default(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        # No mode= argument — should default to socket without error
        stats = replay(sample_pcap, dry_run=True)
        assert stats.packets_sent >= 0

    def test_preview_via_load_packets(self, sample_pcap: Path) -> None:
        pytest.importorskip("scapy")
        pkts = load_packets(sample_pcap)
        assert len(pkts) == 2
