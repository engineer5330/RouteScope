"""Run DNS and TCP checks while retaining the requested result order."""

import asyncio
from time import perf_counter

from .dns import Resolver, resolve
from .models import DiagnosisReport, Options, TargetResult
from .tcp import Connector, probe


async def run_diagnosis(
    options: Options,
    *,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
) -> DiagnosisReport:
    started = perf_counter()
    dns_limit = asyncio.Semaphore(min(options.concurrency, 8))

    async def resolve_limited(host: str):
        async with dns_limit:
            return await resolve(host, options.family, options.timeout_s, resolver)

    dns_results = await asyncio.gather(*(resolve_limited(host) for host in options.hosts))
    targets = [TargetResult(host, dns_result) for host, dns_result in zip(options.hosts, dns_results)]
    tcp_limit = asyncio.Semaphore(options.concurrency)

    async def probe_limited(address, port):
        async with tcp_limit:
            return await probe(address, port, options.timeout_s, connector)

    work = [
        (target, address, port)
        for target in targets
        for address in target.dns.addresses
        for port in options.ports
    ]
    # gather preserves this order even when connections finish in another order.
    results = await asyncio.gather(*(probe_limited(address, port) for _, address, port in work))
    for (target, _, _), result in zip(work, results):
        target.tcp.append(result)

    statuses = (check.status for target in targets for check in target.tcp)
    summary = {name: 0 for name in ("connected", "refused", "timeout", "unreachable", "error")}
    for status in statuses:
        summary[status] += 1
    summary["dns_errors"] = sum(target.dns.status in ("error", "timeout") for target in targets)
    summary["tcp_checks"] = sum(summary[name] for name in ("connected", "refused", "timeout", "unreachable", "error"))

    if summary["connected"] == 0:
        overall = "failed"
    elif summary["dns_errors"] or summary["connected"] != summary["tcp_checks"]:
        overall = "partial"
    else:
        overall = "ok"
    return DiagnosisReport(options, targets, overall, (perf_counter() - started) * 1000, summary)
