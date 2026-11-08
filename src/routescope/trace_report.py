"""Text formatting for route reports; JSON uses the models' explicit schema."""

from .trace_models import TraceReport


def format_trace_text(report: TraceReport) -> str:
    lines = [f"RouteScope trace: {report.status}"]
    for target in report.targets:
        lines.append(f"\n{target.host}")
        if not target.routes:
            lines.append(f"  System resolution: {target.dns.status}; {target.dns.error}")
        if target.dns.truncated:
            lines.append("  Address list truncated to 8 results")
        for route in target.routes:
            lines.append(f"  UDP {route.address} ({route.family}):33434 {route.status}")
            for hop in route.hops:
                probes = []
                for probe in hop.probes:
                    if probe.status == "no_response":
                        probes.append("* (no response)")
                    else:
                        bound = "<" if probe.rtt_less_than else ""
                        detail = f"; {probe.error}" if probe.error else ""
                        probes.append(f"{probe.address} {bound}{probe.rtt_ms:.3f} ms{detail}")
                lines.append(f"    {hop.ttl:2d}  " + " | ".join(probes))
            if route.error:
                lines.append(f"  Reason: {route.error}")
            if route.diagnostics and route.status in ("reached", "incomplete"):
                lines.append(f"  Utility: {route.diagnostics}")
    lines.append("\nSummary: " + ", ".join(f"{value} {name}" for name, value in report.summary.items()))
    lines.append("No response is not proof that a hop or destination is unavailable.")
    return "\n".join(lines)
