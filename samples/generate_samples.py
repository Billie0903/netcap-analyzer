"""Generate small demo captures so the tool can be tested without real traffic.

All IP addresses are from documentation ranges (RFC 5737), so no real hosts are involved.
Run:  python samples/generate_samples.py
"""

import os

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

OUT = os.path.dirname(os.path.abspath(__file__))
SERVER, ATTACKER, EMPLOYEE, DNS_SERVER = "192.0.2.1", "203.0.113.0", "198.51.100.14", "203.0.113.2"


def stamp(packets, start=1_700_000_000.0, step=0.01):
    for i, p in enumerate(packets):
        p.time = start + i * step
    return packets


def normal_traffic():
    pkts = []
    for port in (40001, 40002, 40003):
        pkts += [IP(src=EMPLOYEE, dst=SERVER) / TCP(sport=port, dport=443, flags="S"),
                 IP(src=SERVER, dst=EMPLOYEE) / TCP(sport=443, dport=port, flags="SA"),
                 IP(src=EMPLOYEE, dst=SERVER) / TCP(sport=port, dport=443, flags="A")]
    pkts.append(IP(src=EMPLOYEE, dst=DNS_SERVER) / UDP(sport=52444, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    return pkts


def syn_flood():
    return normal_traffic() + [IP(src=ATTACKER, dst=SERVER) / TCP(sport=54770, dport=443, flags="S") for _ in range(300)]


def icmp_flood():
    return normal_traffic() + [IP(src=ATTACKER, dst=SERVER) / ICMP(type=8) for _ in range(250)]


def port_scan():
    return normal_traffic() + [IP(src=ATTACKER, dst=SERVER) / TCP(sport=50000, dport=p, flags="S") for p in range(1, 101)]


def dns_unreachable():
    query = IP(src="192.51.100.15", dst=DNS_SERVER) / UDP(sport=52444, dport=53) / DNS(rd=1, qd=DNSQR(qname="yummyrecipesforme.com"))
    error = IP(src=DNS_SERVER, dst="192.51.100.15") / ICMP(type=3, code=3) / query
    return [query, error] * 3


SAMPLES = {
    "normal.pcap": normal_traffic,
    "syn_flood.pcap": syn_flood,
    "icmp_flood.pcap": icmp_flood,
    "port_scan.pcap": port_scan,
    "dns_unreachable.pcap": dns_unreachable,
}

if __name__ == "__main__":
    for name, builder in SAMPLES.items():
        wrpcap(os.path.join(OUT, name), stamp(builder()))
        print("wrote", name)
