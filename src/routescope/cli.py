"""Command-line validation and process exit codes."""

import argparse
import asyncio
import math
import sys

from .diagnose import run_diagnosis
from .models import Options
from .report import format_json, format_text
from .trace import run_trace, validate_options
from .trace_models import TraceOptions
from .trace_report import format_trace_text

MAX_HOSTS = 8
MAX_PORTS = 16
MAX_CONCURRENCY = 32


def _ports(value: str) -> tuple[int, ...]:
    items = value.split(",")
    if not items or any(not item.isdecimal() for item in items):
        raise argparse.ArgumentTypeError("ports must be comma-separated integers from 1 to 65535")
    ports = tuple(dict.fromkeys(int(item) for item in items))
    if any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    if len(ports) > MAX_PORTS:
        raise argparse.ArgumentTypeError(f"at most {MAX_PORTS} distinct ports are allowed")
    return ports


def _timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 60 seconds")
    return timeout


def _concurrency(value: str) -> int:
    try:
        concurrency = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("concurrency must be an integer") from exc
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    return concurrency


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="routescope", description="Diagnose DNS, TCP, optional TLS or an explicit route")
    commands = parser.add_subparsers(dest="command", required=True)
    diagnose = commands.add_parser("diagnose", help="check explicit hosts and TCP ports")
    diagnose.add_argument("hosts", metavar="HOST", nargs="+", help="one or more hostnames or IP addresses")
    diagnose.add_argument("--ports", required=True, type=_ports, metavar="80,443", help="comma-separated TCP ports")
    diagnose.add_argument("--family", choices=("ipv4", "ipv6", "both"), default="both")
    diagnose.add_argument("--timeout", type=_timeout, default=3.0, metavar="SECONDS", help="per DNS, TCP or TLS operation (default: 3)")
    diagnose.add_argument("--tls", action="store_true", help="verify TLS on each connected socket, on every specified port")
    diagnose.add_argument("--concurrency", type=_concurrency, default=32, metavar="N", help="maximum concurrent TCP checks (default: 32)")
    diagnose.add_argument("--format", choices=("text", "json"), default="text")
    trace = commands.add_parser("trace", help="trace a route to explicit hosts using system UDP traceroute")
    trace.add_argument("hosts", metavar="HOST", nargs="+")
    trace.add_argument("--family", choices=("ipv4", "ipv6", "both"), default="ipv4")
    trace.add_argument("--max-hops", type=int, default=16, metavar="N", help="hop limit, 1 to 32 (default: 16)")
    trace.add_argument("--probes", type=int, default=1, metavar="N", help="probes per hop, 1 to 3 (default: 1)")
    trace.add_argument("--timeout", type=int, default=2, metavar="SECONDS", help="per probe and DNS wait, integer 1 to 5 (default: 2)")
    trace.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def parse_options(argv: list[str] | None = None) -> Options | TraceOptions:
    parser = build_parser()
    args = parser.parse_args(argv)
    hosts = tuple(dict.fromkeys(args.hosts))
    if args.command == "trace":
        options = TraceOptions(hosts, args.family, args.max_hops, args.probes, args.timeout, args.format)
        try:
            validate_options(options)
        except ValueError as exc:
            parser.error(str(exc))
        return options
    if len(hosts) > MAX_HOSTS:
        parser.error(f"at most {MAX_HOSTS} distinct hosts are allowed")
    for host in hosts:
        if not host.strip() or host != host.strip() or any(char.isspace() for char in host) or len(host) > 253:
            parser.error(f"invalid host: {host!r}")
    return Options(hosts, args.ports, args.family, args.timeout, args.concurrency, args.format, args.tls)


def main(argv: list[str] | None = None) -> int:
    options = parse_options(argv)
    try:
        report = asyncio.run(run_trace(options) if isinstance(options, TraceOptions) else run_diagnosis(options))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    if options.output_format == "json":
        print(format_json(report))
    else:
        print(format_trace_text(report) if isinstance(options, TraceOptions) else format_text(report))
    return 0 if report.status == "ok" else 1
