"""Turn a Report into Markdown or JSON."""

import json

from .analyzer import Report


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def to_markdown(report: Report) -> str:
    lines = [
        f"# NetCap Analyzer report: `{report.file}`",
        "",
        f"- **Packets:** {report.total_packets}",
        f"- **Capture duration:** {report.duration_seconds} s",
        f"- **Findings:** {len(report.findings)}",
        "",
        "## Protocols",
        "",
        "| Protocol | Packets |",
        "|---|---|",
    ]
    lines += [f"| {p} | {c} |" for p, c in report.protocols.items()]
    lines += ["", "## Top sources", "", "| Source IP | Packets |", "|---|---|"]
    lines += [f"| {ip} | {c} |" for ip, c in report.top_sources]
    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("No suspicious activity detected with the current thresholds.")
    else:
        lines += ["| Severity | Rule | Source | Target | Count | MITRE ATT&CK |", "|---|---|---|---|---|---|"]
        lines += [f"| {f.severity} | {f.rule} | {f.source} | {f.target} | {f.count} | {f.mitre} |"
                  for f in report.findings]
        lines.append("")
        for f in report.findings:
            lines.append(f"- **{f.rule}** ({f.source} → {f.target}): {f.description}")
    return "\n".join(lines) + "\n"
