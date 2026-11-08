import asyncio
import errno
import json
import socket
import unittest

from routescope.diagnose import run_diagnosis
from routescope.models import Options
from routescope.report import format_json


def record(address):
    return (socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, 0))


class DiagnosisTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_success_and_stable_order(self):
        async def resolver(host, *args, **kwargs):
            if host == "bad.invalid":
                raise socket.gaierror(socket.EAI_NONAME, "unknown")
            return [record("127.0.0.2"), record("127.0.0.1")]

        async def connector(sock, endpoint):
            if endpoint[0] == "127.0.0.2":
                await asyncio.sleep(0.01)
                raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        options = Options(("good.invalid", "bad.invalid"), (80, 443), concurrency=2)
        report = await run_diagnosis(options, resolver=resolver, connector=connector)
        self.assertEqual(report.status, "partial")
        self.assertEqual(report.summary["connected"], 2)
        self.assertEqual(report.summary["refused"], 2)
        self.assertEqual(report.summary["dns_errors"], 1)
        self.assertEqual(
            [(check.address, check.port) for check in report.targets[0].tcp],
            [("127.0.0.2", 80), ("127.0.0.2", 443), ("127.0.0.1", 80), ("127.0.0.1", 443)],
        )
        document = json.loads(format_json(report))
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["parameters"]["ports"], [80, 443])
        self.assertIn("duration_ms", document["targets"][0]["tcp"][0])

    async def test_global_tcp_concurrency_limit(self):
        active = 0
        maximum = 0

        async def connector(sock, endpoint):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            try:
                await asyncio.sleep(0.01)
            finally:
                active -= 1

        options = Options(("127.0.0.1",), (1, 2, 3, 4, 5), concurrency=2)
        report = await run_diagnosis(options, connector=connector)
        self.assertEqual(report.status, "ok")
        self.assertEqual(maximum, 2)

    async def test_dns_failures_do_not_connect(self):
        async def resolver(host, *args, **kwargs):
            if host == "slow.invalid":
                await asyncio.Future()
            raise socket.gaierror(socket.EAI_NONAME, "controlled DNS failure")

        async def connector(sock, endpoint):
            self.fail("DNS failures must not trigger TCP")

        options = Options(("bad.invalid", "slow.invalid"), (80,), timeout_s=0.01)
        report = await run_diagnosis(options, resolver=resolver, connector=connector)
        self.assertEqual(report.status, "failed")
        self.assertEqual([target.dns.status for target in report.targets], ["error", "timeout"])
        self.assertEqual(report.summary["dns_errors"], 2)
        self.assertEqual(report.summary["tcp_checks"], 0)
