import asyncio
import json
import sys
import unittest
from pathlib import Path


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        script = Path(sys.executable).with_name("routescope")
        self.assertTrue(script.is_file(), "Install the package before running tests; routescope is required")
        self.entrypoints = [(sys.executable, "-I", "-W", "error", "-m", "routescope"), (str(script),)]

    async def run_cli(self, entrypoint, *arguments):
        process = await asyncio.create_subprocess_exec(
            *entrypoint, *arguments,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
            return process.returncode, stdout.decode(), stderr.decode()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def test_entrypoints_dns_tcp_and_reports(self):
        accepted = asyncio.Queue()

        async def handle(reader, writer):
            writer.close()
            await writer.wait_closed()
            accepted.put_nowait(None)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            for entrypoint in self.entrypoints:
                for host in ("localhost", "127.0.0.1"):
                    for output_format in ("json", "text"):
                        with self.subTest(entrypoint=entrypoint, host=host, format=output_format):
                            code, stdout, stderr = await self.run_cli(
                                entrypoint, "diagnose", host, "--ports", str(port),
                                "--family", "ipv4", "--timeout", "5", "--format", output_format,
                            )
                            self.assertEqual(code, 0, stderr)
                            self.assertEqual(stderr, "")
                            if output_format == "json":
                                document = json.loads(stdout)
                                self.assertEqual(document["schema_version"], 1)
                                self.assertEqual(document["status"], "ok")
                                self.assertEqual(document["summary"]["connected"], 1)
                                target = document["targets"][0]
                                self.assertEqual(target["dns"]["status"], "resolved" if host == "localhost" else "literal")
                                self.assertEqual(target["tcp"][0]["port"], port)
                            else:
                                self.assertIn("RouteScope: ok", stdout)
                                self.assertIn("1 connected", stdout)
                            await asyncio.wait_for(accepted.get(), 5)
                with self.subTest(entrypoint=entrypoint, status="partial"):
                    code, stdout, stderr = await self.run_cli(
                        entrypoint, "diagnose", "127.0.0.1", "::1", "--ports", str(port),
                        "--family", "ipv4", "--format", "json",
                    )
                    self.assertEqual(code, 1, stderr)
                    self.assertEqual(stderr, "")
                    document = json.loads(stdout)
                    self.assertEqual(document["status"], "partial")
                    self.assertEqual(document["summary"]["connected"], 1)
                    self.assertEqual(document["summary"]["dns_errors"], 1)
                    await asyncio.wait_for(accepted.get(), 5)
        finally:
            server.close()
            await server.wait_closed()

    async def test_entrypoints_failure_and_usage_exit_codes(self):
        for entrypoint in self.entrypoints:
            with self.subTest(entrypoint=entrypoint):
                code, stdout, stderr = await self.run_cli(
                    entrypoint, "diagnose", "127.0.0.1", "--ports", "80",
                    "--family", "ipv6", "--format", "json",
                )
                self.assertEqual(code, 1, stderr)
                self.assertEqual(stderr, "")
                self.assertEqual(json.loads(stdout)["status"], "failed")
                self.assertEqual(json.loads(stdout)["summary"]["dns_errors"], 1)
                code, stdout, stderr = await self.run_cli(
                    entrypoint, "diagnose", "127.0.0.1", "--ports", "0", "--format", "json",
                )
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)
