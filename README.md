# NetCap Analyzer

![CI](https://github.com/Billie0903/netcap-analyzer/actions/workflows/ci.yml/badge.svg)

A small Python command-line tool that reads a packet capture (`.pcap`) and flags common network attacks. I built it to automate the manual log analysis I practised in the Google Cybersecurity Certificate (tcpdump and Wireshark labs).

## What it detects

| Rule | What it looks for | Severity | MITRE ATT&CK |
|---|---|---|---|
| SYN flood | Many SYN packets from one source with no completed handshake | HIGH | T1498 / T1499 |
| ICMP flood | Many ICMP echo requests (pings) from one source | HIGH | T1498 |
| Port scan | One source contacting many different ports on one host | MEDIUM | T1046 |
| DNS service unreachable | ICMP "UDP port 53 unreachable" replies | MEDIUM | N/A |
| DNS error responses | DNS replies with an error code (for example NXDOMAIN) | LOW | N/A |

It also summarises the capture: packet count, duration, protocols, top source IPs and top destination ports.

## Quick start

```bash
git clone https://github.com/Billie0903/netcap-analyzer.git
cd netcap-analyzer
pip install -r requirements.txt

python samples/generate_samples.py                 # create demo captures
python -m netcap_analyzer samples/syn_flood.pcap   # print a report
python -m netcap_analyzer capture.pcap --md report.md --json report.json
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--syn-threshold` | 100 | Half-open SYNs before a SYN flood is flagged |
| `--icmp-threshold` | 100 | Echo requests before an ICMP flood is flagged |
| `--scan-threshold` | 20 | Distinct ports before a port scan is flagged |
| `--fail-on-high` | off | Exit with code 2 if a HIGH finding exists (for CI pipelines) |

## Example output

```
| Severity | Rule      | Source      | Target    | Count | MITRE ATT&CK                 |
|----------|-----------|-------------|-----------|-------|------------------------------|
| HIGH     | SYN flood | 203.0.113.0 | 192.0.2.1 | 300   | T1498 / T1499 Denial of Service |
```

## Automation (GitHub Actions)

Every push runs the workflow in `.github/workflows/ci.yml`, which:

1. Runs the unit tests on Python 3.10 and 3.12
2. Regenerates the sample captures
3. Analyses each capture and writes the reports to the job summary
4. Uploads the Markdown and JSON reports as build artifacts

## Project structure

```
netcap_analyzer/   analyzer.py (detection rules), report.py (Markdown/JSON), cli.py
samples/           generate_samples.py builds demo captures (documentation IP ranges only)
tests/             pytest unit tests for each detection rule
```

## Limitations and next steps

- Thresholds are simple counts, not time windows. Next: add a per-second rate.
- Spoofed source IPs can spread a flood across many addresses (DDoS). Next: aggregate by target.
- Next: export findings in a SIEM-friendly format (for example JSON lines for Splunk).

## Ethics

Only analyse captures from networks you own or have permission to monitor. The sample captures use documentation IP ranges (RFC 5737).

## License

MIT
