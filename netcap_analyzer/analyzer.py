"""Core analysis logic.

Reads a .pcap/.pcapng file with Scapy, builds a traffic summary and runs
simple detection rules for common network attacks.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
from scapy.layers.inet import UDPerror


@dataclass
class Thresholds:
    syn_flood: int = 100          # half-open SYNs from one source
    icmp_flood: int = 100         # ICMP echo requests from one source
    port_scan: int = 20           # distinct destination ports from one source to one host


@dataclass
class Finding:
    rule: str
    severity: str
    source: str
    target: str
    count: int
    description: str
    mitre: str


@dataclass
class Report:
    file: str
    total_packets: int = 0
    duration_seconds: float = 0.0
    protocols: dict = field(default_factory=dict)
    top_sources: list = field(default_factory=list)
    top_destination_ports: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [asdict(f) if isinstance(f, Finding) else f for f in self.findings]
        return data


def _protocol_name(pkt) -> str:
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        dport, sport = pkt[TCP].dport, pkt[TCP].sport
        if 80 in (dport, sport):
            return "HTTP"
        if 443 in (dport, sport):
            return "HTTPS"
        return "TCP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


def analyze(path: str, thresholds: Thresholds | None = None) -> Report:
    """Analyse a capture file and return a Report."""
    t = thresholds or Thresholds()
    packets = rdpcap(path)
    report = Report(file=path, total_packets=len(packets))
    if not packets:
        return report

    report.duration_seconds = round(float(packets[-1].time - packets[0].time), 3)

    protocols = Counter()
    sources = Counter()
    dst_ports = Counter()
    syn_counts = Counter()          # (src, dst) -> SYNs sent
    ack_counts = Counter()          # (src, dst) -> ACKs completing a handshake
    icmp_echo = Counter()           # (src, dst) -> echo requests
    ports_seen = defaultdict(set)   # (src, dst) -> distinct TCP/UDP destination ports
    dns_unreachable = Counter()     # (dns_server, client) -> ICMP port 53 unreachable
    dns_errors = Counter()          # (dns_server, client) -> DNS responses with an error code

    for pkt in packets:
        protocols[_protocol_name(pkt)] += 1
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        sources[src] += 1

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_ports[tcp.dport] += 1
            flags = str(tcp.flags)
            if flags == "S":
                syn_counts[(src, dst)] += 1
                ports_seen[(src, dst)].add(tcp.dport)
            elif flags == "A":
                ack_counts[(src, dst)] += 1

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            if icmp.type == 8:  # echo request
                icmp_echo[(src, dst)] += 1
            elif icmp.type == 3 and icmp.code == 3 and pkt.haslayer(UDPerror):
                # ICMP "port unreachable" quotes the original UDP packet (UDPerror in Scapy)
                if pkt[UDPerror].dport == 53:
                    dns_unreachable[(src, dst)] += 1

        elif pkt.haslayer(UDP):
            dst_ports[pkt[UDP].dport] += 1
            ports_seen[(src, dst)].add(pkt[UDP].dport)
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt[DNS].rcode != 0:
                dns_errors[(src, dst)] += 1

    report.protocols = dict(protocols.most_common())
    report.top_sources = sources.most_common(5)
    report.top_destination_ports = dst_ports.most_common(5)

    for (src, dst), syns in syn_counts.items():
        half_open = syns - ack_counts.get((src, dst), 0)
        if half_open >= t.syn_flood:
            report.findings.append(Finding(
                "SYN flood", "HIGH", src, dst, half_open,
                f"{half_open} SYN packets without a completed handshake. "
                "This pattern fills the server's connection queue (denial of service).",
                "T1498 / T1499 Network and Endpoint Denial of Service",
            ))

    for (src, dst), count in icmp_echo.items():
        if count >= t.icmp_flood:
            report.findings.append(Finding(
                "ICMP flood", "HIGH", src, dst, count,
                f"{count} ICMP echo requests (pings) from a single source.",
                "T1498 Network Denial of Service",
            ))

    for (src, dst), ports in ports_seen.items():
        if len(ports) >= t.port_scan:
            report.findings.append(Finding(
                "Port scan", "MEDIUM", src, dst, len(ports),
                f"Connection attempts to {len(ports)} different ports on one host.",
                "T1046 Network Service Discovery",
            ))

    for (server, client), count in dns_unreachable.items():
        report.findings.append(Finding(
            "DNS service unreachable", "MEDIUM", server, client, count,
            f"{count} ICMP 'UDP port 53 unreachable' replies: the DNS service is down or blocked.",
            "N/A (availability issue)",
        ))

    for (server, client), count in dns_errors.items():
        report.findings.append(Finding(
            "DNS error responses", "LOW", server, client, count,
            f"{count} DNS responses with an error code (for example NXDOMAIN).",
            "N/A (investigate)",
        ))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    report.findings.sort(key=lambda f: (order[f.severity], -f.count))
    return report
