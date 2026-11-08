import asyncio
import json
import os
import signal
import sys
import unittest
from pathlib import Path

from tls_support import FIXTURES, LocalServer


class TlsEndToEndTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        script = Path(sys.executable).with_name("routescope")
        self.assertTrue(script.is_file(), "Install routescope before running tests")
        self.entrypoints = [(sys.executable, "-I", "-W", "error", "-m", "routescope"), (str(script),)]

    async def run_cli(self, entrypoint, *arguments, interrupt_after=None):
        env = os.environ.copy()
        env["SSL_CERT_FILE"] = str(FIXTURES / "ca.pem")
        env["SSL_CERT_DIR"] = str(FIXTURES)
        env.pop("SSLKEYLOGFILE", None)
        process = await asyncio.create_subprocess_exec(
            *entrypoint, *arguments, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            if interrupt_after is not None:
                await asyncio.wait_for(interrupt_after.wait(), 10)
                process.send_signal(signal.SIGINT)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
            return process.returncode, stdout.decode(), stderr.decode()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def test_both_entrypoints_verified_tls_on_explicit_arbitrary_port(self):
        async with LocalServer() as server:
            for entrypoint in self.entrypoints:
                for output_format in ("text", "json"):
                    with self.subTest(entrypoint=entrypoint, format=output_format):
                        code, stdout, stderr = await self.run_cli(
                            entrypoint, "diagnose", "localhost", "--ports", str(server.port),
                            "--family", "ipv4", "--tls", "--timeout", "5", "--format", output_format,
                        )
                        self.assertEqual(code, 0, stderr + stdout)
                        self.assertEqual(stderr, "")
                        if output_format == "json":
                            document = json.loads(stdout)
                            self.assertEqual(document["status"], "ok")
                            self.assertEqual(document["summary"]["tls_verified"], 1)
                            self.assertEqual(document["targets"][0]["tcp"][0]["tls"]["status"], "verified")
                        else:
                            self.assertIn("TLS verified", stdout)
                            self.assertIn("2040-01-01T00:00:00Z", stdout)
                        await asyncio.wait_for(server.closed.get(), 5)
            self.assertEqual(server.connections, 4)
            self.assertEqual(server.names, ["localhost"] * 4)

    async def test_tls_failure_and_partial_exit_one(self):
        async with LocalServer() as good, LocalServer("plain") as bad:
            for entrypoint in self.entrypoints:
                for ports, status in ((str(bad.port), "failed"), (f"{bad.port},{good.port}", "partial")):
                    with self.subTest(entrypoint=entrypoint, status=status):
                        code, stdout, stderr = await self.run_cli(
                            entrypoint, "diagnose", "127.0.0.1", "--ports", ports,
                            "--tls", "--timeout", "5", "--format", "json",
                        )
                        self.assertEqual(code, 1, stderr + stdout)
                        self.assertEqual(stderr, "")
                        document = json.loads(stdout)
                        self.assertEqual(document["status"], status)
                        self.assertEqual(document["summary"]["tls_handshake_error"], 1)
                        self.assertEqual(document["summary"]["tls_verified"], int(status == "partial"))

    async def test_ctrl_c_during_handshake_closes_connection_and_exits_130(self):
        for entrypoint in self.entrypoints:
            with self.subTest(entrypoint=entrypoint):
                async with LocalServer("stall") as server:
                    code, stdout, stderr = await self.run_cli(
                        entrypoint, "diagnose", "127.0.0.1", "--ports", str(server.port),
                        "--tls", "--timeout", "60", "--format", "json", interrupt_after=server.received,
                    )
                    self.assertEqual(code, 130, stderr)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr.strip(), "Interrupted")
                    await asyncio.wait_for(server.closed.get(), 5)
                    self.assertEqual(server.connections, 1)
