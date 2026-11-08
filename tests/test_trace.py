import contextlib
import io
import json
import socket
import unittest
from unittest.mock import AsyncMock, patch

from routescope.cli import main, parse_options
from routescope.models import Address
from routescope.report import format_json
from routescope.trace import command, parse_output, process_deadline, run_trace, trace_address
from routescope.trace_models import RouteResult, TraceOptions
from routescope.trace_report import format_trace_text


class TraceArgumentTests(unittest.TestCase):
    def test_defaults_limits_deduplication_and_unicode_names(self):
        options = parse_options(["trace", "localhost", "localhost"])
        self.assertEqual(options, TraceOptions(("localhost",)))
        self.assertEqual(process_deadline(options), 37)
        options = parse_options(["trace", "::1", "--family", "both", "--max-hops", "32",
                                 "--probes", "3", "--timeout", "5", "--format", "json"])
        self.assertEqual(options.max_hops, 32)
        self.assertEqual(options.timeout_s, 5)
        for host in ("пример.рф", "example.com.", "fe80::1%en0", "fe80::1%7"):
            self.assertEqual(parse_options(["trace", host]).hosts, (host,))

    def test_invalid_arguments_do_no_work(self):
        cases = [[], ["--max-hops", "0"], ["--max-hops", "33"], ["--probes", "4"],
                 ["--probes", "0"], ["--timeout", "0"], ["--timeout", "6"], ["--timeout", "1.5"],
                 ["--family", "wrong"], ["--ports", "80"], ["--tls"]]
        commands = [["trace"]] + [["trace", "localhost", *case] for case in cases[1:]]
        commands += [["trace", host] for host in ("", "bad host", "x;touch", "$(id)", "x/y", "https://x",
                                                       "127.0.0.0/8", "bad\nname", "fe80::1%x/y", "-I")]
        commands += [["trace", *[f"host{i}.invalid" for i in range(5)]]]
        for argv in commands:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with patch("routescope.cli.run_trace") as trace, patch("routescope.cli.run_diagnosis") as diagnose:
                    with self.assertRaises(SystemExit) as exc:
                        main(argv)
                    self.assertEqual(exc.exception.code, 2)
                    trace.assert_not_called()
                    diagnose.assert_not_called()

    def test_both_adapters_use_fixed_port_and_numeric_addresses(self):
        options = TraceOptions(("localhost",), probes=2, max_hops=5, timeout_s=1)
        for platform in ("darwin", "linux"):
            for host, family in (("127.0.0.1", "ipv4"), ("::1", "ipv6")):
                with self.subTest(platform=platform, family=family):
                    with patch("routescope.trace.shutil.which", side_effect=lambda name, **kw: "/tool/" + name):
                        args = command(Address(host, family), options, platform)
                    self.assertEqual(args[-1], host)
                    for flag, value in (("-p", "33434"), ("-m", "5"), ("-q", "2"), ("-w", "1")):
                        self.assertEqual(args[args.index(flag) + 1], value)
                    self.assertIn("-n", args)
                    if platform == "darwin":
                        self.assertEqual(args[0], "/tool/traceroute" + ("6" if family == "ipv6" else ""))
                        self.assertIn("-e", args)
                    else:
                        self.assertIn("-4" if family == "ipv4" else "-6", args)
                        self.assertIn("-U", args)
                        self.assertEqual(args[args.index("-N") + 1], "1")
        with self.assertRaises(ValueError):
            command(Address("-I", "ipv4"), options, "linux")


class TraceParserTests(unittest.TestCase):
    def test_apple_ipv4_multiple_responders_timeouts_and_annotations(self):
        output = ("traceroute to 192.0.2.10 (192.0.2.10), 4 hops max, 40 byte packets\n"
                  " 1  192.0.2.1  0.123 ms  0.234 ms  192.0.2.2  1.000 ms\n"
                  " 2  * * *\n"
                  " 3  192.0.2.10  2.0 ms !H  3 ms !N  4 ms !\n")
        hops, error = parse_output(output, "ipv4", "darwin", 4, 3)
        self.assertIsNone(error)
        self.assertEqual([h.ttl for h in hops], [1, 2, 3])
        self.assertEqual([p.address for p in hops[0].probes], ["192.0.2.1", "192.0.2.1", "192.0.2.2"])
        self.assertEqual(hops[0].probes[0].rtt_ms, 0.123)
        self.assertTrue(all(p.status == "no_response" and p.address is None for p in hops[1].probes))
        self.assertEqual([p.status for p in hops[2].probes], ["error", "error", "reply"])
        self.assertEqual(hops[2].probes[0].error, "host unreachable")

    def test_linux_ipv6_and_apple_ipv6_continuations(self):
        output = (" 1  2001:db8::1  0.1 ms *\n"
                  "    2001:db8::2  <1 ms\n"
                  " 2  2001:db8::10  1.2ms !P  1.3 ms !A  1.4 ms\n")
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                hops, error = parse_output(output, "ipv6", platform, 4, 3)
                self.assertIsNone(error)
                self.assertEqual(hops[0].probes[2].address, "2001:db8::2")
                self.assertTrue(hops[0].probes[2].rtt_less_than)
                self.assertEqual(hops[0].probes[2].rtt_ms, 1)
                self.assertEqual(hops[1].probes[0].error, "administratively prohibited" if platform == "darwin" else "protocol unreachable")

    def test_unknown_output_is_never_silently_successful(self):
        for output in ("unexpected version output", "1 0.5 ms", "1 127.0.0.1 1 ms strange",
                       "2 *", "1 * *", "1 ::1 1 ms", "1 127.0.0.1", "1 127.0.0.1 1 ms\n1 *"):
            with self.subTest(output=output):
                _, error = parse_output(output, "ipv4", "linux", 4, 1)
                self.assertTrue(error)

    def test_parse_errors_preserve_observations_without_inventing_probes(self):
        for output in ("1 127.0.0.1 1 ms\nunsupported footer",
                       "1 127.0.0.1 1 ms\n2 127.0.0.2 2 ms invalid"):
            hops, error = parse_output(output, "ipv4", "linux", 4, 1)
            self.assertTrue(error)
            self.assertEqual(hops[0].probes[0].rtt_ms, 1)
            self.assertEqual(hops[0].probes[0].address, "127.0.0.1")
        hops, error = parse_output("1 127.0.0.1 1 ms", "ipv4", "linux", 4, 3)
        self.assertTrue(error)
        self.assertEqual(len(hops[0].probes), 1)


class TraceOrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_order_first_address_per_family_partial_dns_and_json(self):
        async def resolver(host, *args, **kwargs):
            if host == "bad.invalid":
                raise socket.gaierror(socket.EAI_NONAME, "controlled DNS error")
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.2", 0))]

        async def trace(address, options):
            return RouteResult(address.value, address.family, "reached" if address.family == "ipv4" else "incomplete")

        with patch("routescope.trace.trace_address", side_effect=trace) as adapter:
            report = await run_trace(TraceOptions(("good.invalid", "bad.invalid"), family="both"), resolver=resolver)
        self.assertEqual(adapter.await_count, 2)
        self.assertEqual(report.status, "partial")
        self.assertEqual([r.address for r in report.targets[0].routes], ["127.0.0.1", "::1"])
        self.assertEqual(report.targets[1].routes, [])
        self.assertEqual(report.summary["dns_errors"], 1)
        doc = json.loads(format_json(report))
        self.assertEqual(doc["command"], "trace")
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["parameters"]["hosts"], ["good.invalid", "bad.invalid"])
        self.assertIn("not proof", format_trace_text(report))

    async def test_dns_timeout_and_invalid_api_options_never_start_utility(self):
        async def resolver(*args, **kwargs):
            raise TimeoutError("controlled timeout")

        with patch("routescope.trace.trace_address") as adapter:
            report = await run_trace(TraceOptions(("slow.invalid",)), resolver=resolver)
            self.assertEqual(report.status, "failed")
            self.assertEqual(report.targets[0].dns.status, "timeout")
            with self.assertRaises(ValueError):
                await run_trace(TraceOptions(("localhost",), max_hops=33))
            adapter.assert_not_called()

    async def test_missing_utility_and_unsupported_platform(self):
        options = TraceOptions(("127.0.0.1",))
        with patch("routescope.trace.shutil.which", return_value=None), patch("routescope.trace.asyncio.create_subprocess_exec") as spawn:
            result = await trace_address(Address("127.0.0.1", "ipv4"), options)
            self.assertEqual(result.status, "unavailable")
            self.assertIn("not installed", result.error)
            spawn.assert_not_called()
        with patch("routescope.trace.sys.platform", "win32"):
            result = await trace_address(Address("127.0.0.1", "ipv4"), options)
            self.assertEqual(result.status, "unavailable")

    async def test_process_start_errors_are_reported(self):
        for error, status in ((PermissionError("permission denied"), "error"), (FileNotFoundError("removed"), "unavailable")):
            with patch("routescope.trace.shutil.which", return_value="/fake/traceroute"):
                with patch("routescope.trace.asyncio.create_subprocess_exec", new=AsyncMock(side_effect=error)):
                    result = await trace_address(Address("127.0.0.1", "ipv4"), TraceOptions(("127.0.0.1",)))
                    self.assertEqual(result.status, status)
                    self.assertIn(str(error), result.error)
