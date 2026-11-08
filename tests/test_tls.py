import asyncio
import errno
import json
import socket
import ssl
import unittest
from unittest.mock import patch

from routescope.diagnose import run_diagnosis
from routescope.models import Address, Options, TlsResult
from routescope.report import format_json, format_text
from routescope.tcp import probe
from routescope.tls import server_identity
from tls_support import LocalServer, client_context


class TlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_verified_same_socket_no_resolution_sni_metadata_and_cleanup(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for host, family, identity in (("127.0.0.1", "ipv4", "localhost"), ("::1", "ipv6", "::1")):
                with self.subTest(version=version, family=family):
                    async with LocalServer(host=host, version=version) as server:
                        sockets = []
                        loop = asyncio.get_running_loop()

                        async def connect(sock, endpoint):
                            sockets.append(sock)
                            await loop.sock_connect(sock, endpoint)

                        with patch.object(loop, "getaddrinfo", side_effect=AssertionError("second resolution")):
                            result = await probe(Address(host, family), server.port, 5, connect,
                                                 tls_host=identity, tls_context=client_context())
                        self.assertEqual(result.status, "connected")
                        self.assertEqual(result.tls.status, "verified", result.tls.error)
                        self.assertEqual(result.tls.version, "TLSv1.2" if version == ssl.TLSVersion.TLSv1_2 else "TLSv1.3")
                        self.assertTrue(result.tls.cipher)
                        self.assertEqual(result.tls.certificate_not_before, "2020-01-01T00:00:00Z")
                        self.assertEqual(result.tls.certificate_not_after, "2040-01-01T00:00:00Z")
                        self.assertGreater(result.tls.duration_ms, 0)
                        await asyncio.wait_for(server.closed.get(), 5)
                        self.assertEqual(len(sockets), 1)
                        self.assertEqual(sockets[0].fileno(), -1)
                        self.assertEqual(server.connections, 1)
                        self.assertEqual(server.names, ["localhost" if identity == "localhost" else None])
                        self.assertTrue(all(not data for data in server.application_data))

    async def test_certificate_trust_and_name_failures(self):
        for trusted, identity in ((False, "localhost"), (True, "wrong.invalid")):
            with self.subTest(trusted=trusted, identity=identity):
                async with LocalServer() as server:
                    result = await probe(Address("127.0.0.1", "ipv4"), server.port, 5,
                                         tls_host=identity, tls_context=client_context(trusted))
                    self.assertEqual(result.status, "connected")
                    self.assertEqual(result.tls.status, "certificate_error")
                    self.assertIsNotNone(result.tls.verify_code)
                    self.assertTrue(result.tls.error)
                    self.assertIsNone(result.tls.certificate_not_after)
                    if trusted:
                        self.assertIn("mismatch", result.tls.error.lower())
                    await asyncio.wait_for(server.closed.get(), 5)
                    self.assertEqual(server.connections, 1)

    async def test_plain_service_is_handshake_error(self):
        async with LocalServer("plain") as server:
            result = await probe(Address("127.0.0.1", "ipv4"), server.port, 5,
                                 tls_host="localhost", tls_context=client_context())
            self.assertEqual(result.status, "connected")
            self.assertEqual(result.tls.status, "handshake_error")
            await asyncio.wait_for(server.closed.get(), 5)

    async def test_timeout_and_cancellation_close_original_socket(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                async with LocalServer("stall") as server:
                    sockets = []

                    async def connect(sock, endpoint):
                        sockets.append(sock)
                        await asyncio.get_running_loop().sock_connect(sock, endpoint)

                    task = asyncio.create_task(probe(
                        Address("127.0.0.1", "ipv4"), server.port, 5 if cancel else 0.1,
                        connect, tls_host="localhost", tls_context=client_context(),
                    ))
                    await asyncio.wait_for(server.received.wait(), 5)
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        result = await task
                        self.assertEqual(result.status, "connected")
                        self.assertEqual(result.tls.status, "timeout")
                    self.assertEqual(sockets[0].fileno(), -1)
                    await asyncio.wait_for(server.closed.get(), 5)

    async def test_tls_skipped_after_tcp_failure(self):
        async def refused(sock, endpoint):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "controlled refusal")

        with patch("routescope.tcp.handshake") as handshake:
            result = await probe(Address("127.0.0.1", "ipv4"), 1234, 5, refused, tls_host="localhost")
        self.assertEqual(result.status, "refused")
        self.assertEqual(result.tls.status, "skipped")
        self.assertEqual(result.tls.duration_ms, 0)
        handshake.assert_not_called()

    async def test_disabled_tls_never_sends_client_hello(self):
        async with LocalServer("stall") as server:
            with patch("routescope.tcp.handshake") as handshake:
                result = await probe(Address("127.0.0.1", "ipv4"), server.port, 5)
            self.assertEqual(result.status, "connected")
            self.assertIsNone(result.tls)
            handshake.assert_not_called()
            await asyncio.wait_for(server.closed.get(), 5)

    async def test_tls_partial_status_summary_order_reports_and_concurrency(self):
        context = client_context()
        async with LocalServer() as good, LocalServer("plain") as bad:
            options = Options(("127.0.0.1",), (bad.port, good.port), concurrency=1, tls=True)
            with patch("routescope.tls.ssl.create_default_context", return_value=context):
                report = await run_diagnosis(options)
            self.assertEqual(report.status, "partial")
            self.assertEqual(report.summary["connected"], 2)
            self.assertEqual(report.summary["tls_verified"], 1)
            self.assertEqual(report.summary["tls_handshake_error"], 1)
            self.assertEqual(report.summary["tls_checks"], 2)
            self.assertEqual([check.port for check in report.targets[0].tcp], [bad.port, good.port])
            self.assertEqual([check.tls.status for check in report.targets[0].tcp], ["handshake_error", "verified"])
            document = json.loads(format_json(report))
            self.assertEqual(document["schema_version"], 2)
            self.assertTrue(document["parameters"]["tls"])
            self.assertEqual(document["targets"][0]["tcp"][1]["tls"]["status"], "verified")
            text = format_text(report)
            self.assertIn("TLS verified", text)
            self.assertIn("TLS handshake_error", text)
            self.assertIn("cipher", text)
            self.assertIn("2040-01-01", text)

    async def test_global_limit_includes_whole_tls_handshake(self):
        active = 0
        maximum = 0

        async def handshake(*args):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            try:
                await asyncio.sleep(0.01)
                return TlsResult("verified", 10)
            finally:
                active -= 1

        async def connect(sock, endpoint):
            pass

        with patch("routescope.tcp.handshake", side_effect=handshake):
            report = await run_diagnosis(
                Options(("127.0.0.1",), (1, 2, 3, 4, 5), concurrency=2, tls=True), connector=connect,
            )
        self.assertEqual(report.status, "ok")
        self.assertEqual(maximum, 2)
        self.assertEqual(active, 0)

    def test_scoped_ip_identity(self):
        self.assertEqual(server_identity("fe80::1%en0"), "fe80::1")
        self.assertEqual(server_identity("localhost"), "localhost")
