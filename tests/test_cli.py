import contextlib
import io
import json
import unittest
from unittest.mock import AsyncMock, patch

from routescope.cli import main, parse_options
from routescope.models import Address, DiagnosisReport, DnsResult, Options, TargetResult, TcpResult


class CliTests(unittest.TestCase):
    def test_arguments_and_limits(self):
        options = parse_options(["diagnose", "localhost", "localhost", "--ports", "80,443,80"])
        self.assertEqual(options.hosts, ("localhost",))
        self.assertEqual(options.ports, (80, 443))
        self.assertFalse(options.tls)
        self.assertTrue(parse_options(["diagnose", "localhost", "--ports", "8000", "--tls"]).tls)
        for argv in (
            ["diagnose", "localhost", "--ports", "0"],
            ["diagnose", "localhost", "--ports", "1-100"],
            ["diagnose", "localhost", "--ports", "80", "--timeout", "nan"],
            ["diagnose", "localhost", "--ports", "80", "--concurrency", "33"],
            ["diagnose", "localhost", "--ports", "80", "--family", "wrong"],
            ["diagnose", "bad host", "--ports", "80"],
            ["diagnose", "localhost"],
            ["diagnose", "localhost", "--ports", "65536"],
            ["diagnose", "localhost", "--ports", "80,"],
            ["diagnose", "localhost", "--ports", "-1"],
            ["diagnose", "localhost", "--ports", "80", "--timeout", "inf"],
            ["diagnose", "localhost", "--ports", "80", "--timeout", "0"],
            ["diagnose", "localhost", "--ports", "80", "--timeout", "61"],
            ["diagnose", "localhost", "--ports", "80", "--concurrency", "0"],
            ["diagnose", "localhost", "--ports", "80", "--concurrency", "1.5"],
            ["diagnose", *[f"host{i}.invalid" for i in range(9)], "--ports", "80"],
            ["diagnose", "localhost", "--ports", ",".join(str(i) for i in range(1, 18))],
        ):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with patch("routescope.cli.run_diagnosis") as diagnose:
                    with self.assertRaises(SystemExit) as raised:
                        main(argv)
                    self.assertEqual(raised.exception.code, 2)
                    diagnose.assert_not_called()

    def test_json_stdout_and_exit_codes(self):
        options = Options(("127.0.0.1",), (80,), output_format="json")
        target = TargetResult(
            "127.0.0.1",
            DnsResult("literal", 0.1, [Address("127.0.0.1", "ipv4")]),
            [TcpResult("127.0.0.1", "ipv4", 80, "refused", 1.0)],
        )
        report = DiagnosisReport(options, [target], "failed", 1.1, {
            "connected": 0, "refused": 1, "timeout": 0, "unreachable": 0,
            "error": 0, "dns_errors": 0, "tcp_checks": 1,
        })
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("routescope.cli.run_diagnosis", new=AsyncMock(return_value=report)):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["diagnose", "127.0.0.1", "--ports", "80", "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "failed")
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)

    def test_success_and_partial_exit_codes(self):
        options = Options(("127.0.0.1",), (80,))
        for status, expected in (("ok", 0), ("partial", 1), ("failed", 1)):
            report = DiagnosisReport(options, [], status, 0, {})
            with self.subTest(status=status):
                with patch("routescope.cli.run_diagnosis", new=AsyncMock(return_value=report)):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(main(["diagnose", "127.0.0.1", "--ports", "80", "--format", "json"]), expected)

    def test_interrupt_exit_code(self):
        with patch("routescope.cli.run_diagnosis", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = main(["diagnose", "127.0.0.1", "--ports", "80"])
        self.assertEqual(code, 130)
        self.assertIn("Interrupted", stderr.getvalue())
