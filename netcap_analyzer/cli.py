"""Command-line interface.

Usage:
    python -m netcap_analyzer capture.pcap
    python -m netcap_analyzer capture.pcap --json report.json --md report.md
"""

import argparse
import sys

from .analyzer import Thresholds, analyze
from .report import to_json, to_markdown


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a packet capture for suspicious traffic.")
    parser.add_argument("pcap", help="Path to a .pcap or .pcapng file")
    parser.add_argument("--json", help="Write the report as JSON to this file")
    parser.add_argument("--md", help="Write the report as Markdown to this file")
    parser.add_argument("--syn-threshold", type=int, default=100)
    parser.add_argument("--icmp-threshold", type=int, default=100)
    parser.add_argument("--scan-threshold", type=int, default=20)
    parser.add_argument("--fail-on-high", action="store_true",
                        help="Exit with code 2 if any HIGH severity finding is detected (useful in CI)")
    args = parser.parse_args(argv)

    report = analyze(args.pcap, Thresholds(args.syn_threshold, args.icmp_threshold, args.scan_threshold))
    md = to_markdown(report)
    print(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(report))
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md)

    if args.fail_on_high and any(f.severity == "HIGH" for f in report.findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
