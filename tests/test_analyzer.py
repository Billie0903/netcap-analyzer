import os
import sys

import pytest
from scapy.all import wrpcap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "samples"))
import generate_samples as gs  # noqa: E402

from netcap_analyzer.analyzer import analyze  # noqa: E402
from netcap_analyzer.cli import main  # noqa: E402


@pytest.fixture
def capture(tmp_path):
    def _make(builder):
        path = tmp_path / "capture.pcap"
        wrpcap(str(path), gs.stamp(builder()))
        return str(path)
    return _make


def rules(report):
    return {f.rule for f in report.findings}


def test_normal_traffic_has_no_findings(capture):
    report = analyze(capture(gs.normal_traffic))
    assert report.findings == []
    assert report.total_packets == 10


def test_detects_syn_flood(capture):
    report = analyze(capture(gs.syn_flood))
    assert "SYN flood" in rules(report)
    finding = next(f for f in report.findings if f.rule == "SYN flood")
    assert finding.source == gs.ATTACKER and finding.severity == "HIGH"


def test_detects_icmp_flood(capture):
    assert "ICMP flood" in rules(analyze(capture(gs.icmp_flood)))


def test_detects_port_scan(capture):
    assert "Port scan" in rules(analyze(capture(gs.port_scan)))


def test_detects_dns_unreachable(capture):
    report = analyze(capture(gs.dns_unreachable))
    finding = next(f for f in report.findings if f.rule == "DNS service unreachable")
    assert finding.count == 3


def test_cli_fail_on_high_returns_2(capture, tmp_path):
    path = capture(gs.syn_flood)
    out = tmp_path / "r.json"
    assert main([path, "--json", str(out), "--fail-on-high"]) == 2
    assert out.exists()
