"""Human-readable and stable JSON serialization."""

import json

from .models import DiagnosisReport


def format_json(report: DiagnosisReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))


def format_text(report: DiagnosisReport) -> str:
    lines = [f"RouteScope: {report.status}"]
    for target in report.targets:
        dns = target.dns
        lines.append(f"\n{target.host}")
        if dns.status == "literal":
            lines.append(f"  Numeric address: {dns.addresses[0].value} ({dns.addresses[0].family}); no system resolution")
        elif dns.addresses:
            addresses = ", ".join(f"{item.value} ({item.family})" for item in dns.addresses)
            lines.append(f"  System resolution: {dns.status}, {dns.duration_ms:.1f} ms; {addresses}")
        else:
            lines.append(f"  System resolution: {dns.status}, {dns.duration_ms:.1f} ms; {dns.error}")
        if dns.truncated:
            lines.append("  Address list truncated to 8 results")
        for check in target.tcp:
            detail = f"; {check.error}" if check.error else ""
            lines.append(
                f"  TCP {check.address} ({check.family}):{check.port} {check.status} "
                f"in {check.duration_ms:.1f} ms{detail}"
            )
    summary = report.summary
    lines.append(
        "\nSummary: "
        f"{summary['connected']} connected, {summary['refused']} refused, "
        f"{summary['timeout']} timed out, {summary['unreachable']} unreachable, "
        f"{summary['error']} other errors, {summary['dns_errors']} DNS errors"
    )
    return "\n".join(lines)
