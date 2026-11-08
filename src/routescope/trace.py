"""Bounded UDP traceroute adapters. No shell, privilege elevation or reverse DNS."""

import asyncio
import contextlib
import ipaddress
import os
import re
import shutil
import signal
import sys
from time import perf_counter

from .dns import Resolver, resolve
from .models import Address
from .trace_models import (
    MAX_HOPS, MAX_PROBES, MAX_TRACE_HOSTS, MAX_WAIT, RouteHop, RouteProbe,
    RouteResult, TraceOptions, TraceReport, TraceTarget,
)


def validate_host(host: str) -> None:
    if not host or len(host) > 253 or host != host.strip():
        raise ValueError(f"invalid trace host: {host!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.removesuffix(".").encode("idna").decode("ascii").split(".")
        if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
            raise ValueError(f"invalid trace host: {host!r}")
    else:
        if "%" in host and not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", host.partition("%")[2]):
            raise ValueError(f"invalid IPv6 zone: {host!r}")


def validate_options(options: TraceOptions) -> None:
    if not 1 <= len(options.hosts) <= MAX_TRACE_HOSTS:
        raise ValueError(f"trace accepts 1 to {MAX_TRACE_HOSTS} distinct hosts")
    for host in options.hosts:
        validate_host(host)
    for value, maximum, name in ((options.max_hops, MAX_HOPS, "max-hops"),
                                 (options.probes, MAX_PROBES, "probes"),
                                 (options.timeout_s, MAX_WAIT, "timeout")):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer from 1 to {maximum}")
    if options.family not in ("ipv4", "ipv6", "both") or options.output_format not in ("text", "json"):
        raise ValueError("invalid trace family or format")


def command(address: Address, options: TraceOptions, platform: str) -> list[str]:
    """Only validated numeric destinations and bounded numbers reach the utility."""
    validate_options(options)
    ip = ipaddress.ip_address(address.value)
    if ("ipv4" if ip.version == 4 else "ipv6") != address.family:
        raise ValueError("trace address does not match its family")
    validate_host(address.value)
    if platform == "darwin":
        name = "traceroute" if address.family == "ipv4" else "traceroute6"
        mode = ["-e"]  # Apple's fixed UDP destination port mode.
    elif platform == "linux":
        name = "traceroute"
        mode = ["-4" if address.family == "ipv4" else "-6", "-U", "-N", "1"]
    else:
        raise NotImplementedError(f"route tracing is not supported on {platform}")
    path = os.environ.get("PATH", os.defpath) + os.pathsep + "/usr/sbin:/sbin"
    executable = shutil.which(name, path=path)
    if executable is None:
        raise FileNotFoundError(f"{name} is not installed or executable; install the system traceroute utility")
    return [executable, *mode, "-n", "-p", "33434", "-m", str(options.max_hops),
            "-q", str(options.probes), "-w", str(options.timeout_s), str(ip)]


def _annotation(code: str, family: str, platform: str) -> str:
    if code == "!":
        return "reply TTL/hop limit is at most 1"
    reasons = {"!H": "host unreachable", "!N": "network unreachable",
               "!P": "protocol unreachable", "!S": "source route failed",
               "!X": "communication administratively prohibited",
               "!A": "communication administratively prohibited", "!V": "host precedence violation",
               "!C": "precedence cutoff"}
    if platform == "darwin" and family == "ipv6":
        reasons.update({"!P": "administratively prohibited", "!S": "not a neighbour", "!A": "address unreachable"})
    if code.startswith("!F"):
        return "fragmentation needed " + code
    return reasons.get(code, "ICMP error " + code)


def parse_output(output: str, family: str, platform: str, max_hops: int, probes: int) -> tuple[list[RouteHop], str | None]:
    """Parse numeric Apple/Linux output; retain prior hops on format errors."""
    groups: list[tuple[int, str]] = []
    grouping_error = None
    for line in output.splitlines():
        if not line.strip() or line.startswith(("traceroute to ", "traceroute6 to ")):
            continue
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if match:
            groups.append((int(match[1]), match[2]))
        elif groups and line[:1].isspace():
            ttl, body = groups[-1]
            groups[-1] = (ttl, body + " " + line.strip())
        else:
            grouping_error = f"unrecognized traceroute output: {line[:200]}"
            break

    hops: list[RouteHop] = []
    for ttl, body in groups:
        if ttl != len(hops) + 1 or ttl > max_hops:
            return hops, f"unexpected hop number: {ttl}"
        hop = RouteHop(ttl)
        hops.append(hop)
        address = None
        tokens = re.findall(r"<?\d+(?:\.\d+)?\s*ms|\S+", body)
        for token in tokens:
            if token == "*":
                hop.probes.append(RouteProbe("no_response", error="no response within probe timeout"))
            elif re.fullmatch(r"<?\d+(?:\.\d+)?\s*ms", token):
                if address is None:
                    return hops, f"missing address for RTT at hop {ttl}"
                value = token.removesuffix("ms").strip()
                hop.probes.append(RouteProbe("reply", address, float(value.lstrip("<")), value.startswith("<")))
            elif token.startswith("!") and hop.probes and hop.probes[-1].status == "reply":
                probe = hop.probes[-1]
                probe.annotation = token
                probe.error = _annotation(token, family, platform)
                if token != "!":
                    probe.status = "error"
            else:
                try:
                    ip = ipaddress.ip_address(token.strip("()"))
                    if ip.version != (4 if family == "ipv4" else 6):
                        raise ValueError("wrong family")
                    address = str(ip)
                except ValueError:
                    return hops, f"unrecognized token at hop {ttl}: {token[:100]}"
            if len(hop.probes) > probes:
                return hops, f"too many probes at hop {ttl}"
        if not hop.probes:
            return hops, f"missing probe results at hop {ttl}"
        if len(hop.probes) != probes:
            return hops, f"incomplete probe results at hop {ttl}"
    return hops, grouping_error


async def _stop(process: asyncio.subprocess.Process) -> None:
    """Stop the child's session, escalate after a grace period and reap it."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), 1)
    except TimeoutError:
        pass
    # Also stop any descendants that kept the pipes open after the leader exited.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    await process.wait()


async def trace_address(address: Address, options: TraceOptions) -> RouteResult:
    started = perf_counter()
    result = RouteResult(address.value, address.family, "error")
    try:
        args = command(address, options, sys.platform)
    except (FileNotFoundError, NotImplementedError) as exc:
        result.status, result.error = "unavailable", str(exc)
        return result
    result.utility = args[0]
    env = dict(os.environ, LC_ALL="C", LANG="C")
    spawning = asyncio.create_task(asyncio.create_subprocess_exec(
        *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True,
    ))
    try:
        process = await asyncio.shield(spawning)
    except asyncio.CancelledError:
        # Cancellation can arrive after the OS spawned a child but before the
        # asyncio Process object was delivered. Recover ownership before exit.
        try:
            process = await spawning
        except OSError:
            pass
        else:
            await _stop(process)
            await process.communicate()
        raise
    except OSError as exc:
        result.error = f"cannot start traceroute: {exc}"
        result.status = "unavailable" if isinstance(exc, FileNotFoundError) else "error"
        return result

    # At most one probe at a time, plus startup/exit allowance for the utility.
    deadline = process_deadline(options)
    communication = asyncio.create_task(process.communicate())
    timed_out = False
    try:
        try:
            stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), deadline)
        except TimeoutError:
            timed_out = True
            await _stop(process)
            stdout, stderr = await communication
    except BaseException:
        await _stop(process)
        await communication
        raise
    result.duration_ms = (perf_counter() - started) * 1000
    result.returncode = process.returncode
    result.diagnostics = stderr.decode("utf-8", errors="replace").strip() or None
    result.hops, parse_error = parse_output(stdout.decode("utf-8", errors="replace"),
                                            address.family, sys.platform, options.max_hops, options.probes)
    if timed_out:
        result.status, result.error = "timeout", f"traceroute exceeded its {deadline} second process deadline"
    elif process.returncode != 0:
        result.error = result.diagnostics or f"traceroute exited with code {process.returncode}"
    elif parse_error or not result.hops:
        result.error = parse_error or "traceroute produced no hop results"
    elif any(probe.status == "reply" and
             ipaddress.ip_address(probe.address.partition("%")[0]) == ipaddress.ip_address(address.value.partition("%")[0])
             for hop in result.hops for probe in hop.probes):
        result.status = "reached"
    else:
        result.status, result.error = "incomplete", "destination response not observed within hop/probe limits"
    return result


def process_deadline(options: TraceOptions) -> int:
    return options.max_hops * options.probes * options.timeout_s + 5


async def run_trace(options: TraceOptions, *, resolver: Resolver | None = None) -> TraceReport:
    validate_options(options)  # Also protect direct API callers before any DNS/process work.
    started = perf_counter()
    targets = []
    for host in dict.fromkeys(options.hosts):
        dns = await resolve(host, options.family, options.timeout_s, resolver)
        target = TraceTarget(host, dns)
        # One address per available requested family, always IPv4 then IPv6.
        for family in ("ipv4", "ipv6"):
            address = next((address for address in dns.addresses if address.family == family), None)
            if address is not None:
                target.routes.append(await trace_address(address, options))
        targets.append(target)
    routes = [route for target in targets for route in target.routes]
    summary = {status: sum(route.status == status for route in routes)
               for status in ("reached", "incomplete", "timeout", "unavailable", "error")}
    summary["dns_errors"] = sum(target.dns.status in ("error", "timeout") for target in targets)
    summary["route_checks"] = len(routes)
    status = "failed" if not summary["reached"] else (
        "ok" if summary["reached"] == len(routes) and not summary["dns_errors"] else "partial")
    return TraceReport(options, targets, status, (perf_counter() - started) * 1000, summary)
