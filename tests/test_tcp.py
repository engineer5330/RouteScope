import asyncio
import errno
import socket
import unittest
from unittest.mock import AsyncMock, patch

from routescope.models import Address
from routescope.tcp import probe


class TcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_server(self):
        for host, family in (("127.0.0.1", "ipv4"), ("::1", "ipv6")):
            with self.subTest(family=family):
                accepted = asyncio.Event()

                async def handle(reader, writer):
                    writer.close()
                    await writer.wait_closed()
                    accepted.set()

                server = await asyncio.start_server(handle, host, 0)
                port = server.sockets[0].getsockname()[1]
                try:
                    result = await probe(Address(host, family), port, 5)
                    self.assertEqual(result.status, "connected")
                    await asyncio.wait_for(accepted.wait(), 5)
                finally:
                    server.close()
                    await server.wait_closed()

    async def test_timeout_and_socket_closed(self):
        sockets = []

        async def slow(sock, endpoint):
            sockets.append(sock)
            await asyncio.Future()

        result = await probe(Address("127.0.0.1", "ipv4"), 80, 0.001, slow)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(sockets[0].fileno(), -1)

    async def test_unreachable_is_distinct(self):
        async def unreachable(sock, endpoint):
            raise OSError(errno.ENETUNREACH, "network unreachable")

        result = await probe(Address("127.0.0.1", "ipv4"), 80, 1, unreachable)
        self.assertEqual(result.status, "unreachable")

    async def test_cancellation_closes_socket(self):
        sockets = []
        entered = asyncio.Event()

        async def pending(sock, endpoint):
            sockets.append(sock)
            entered.set()
            await asyncio.Future()

        task = asyncio.create_task(probe(Address("127.0.0.1", "ipv4"), 80, 10, pending))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(sockets[0].fileno(), -1)

    async def test_ipv6_scope_is_passed_without_resolving_again(self):
        loop = asyncio.get_running_loop()
        for value, endpoint in (
            ("::1", ("::1", 443, 0, 0)),
            ("fe80::1%7", ("fe80::1", 443, 0, 7)),
            ("fe80::1%test-interface", ("fe80::1", 443, 0, 7)),
        ):
            with self.subTest(value=value):
                connector = AsyncMock()
                with patch("routescope.tcp.socket.if_nametoindex", return_value=7):
                    with patch.object(loop, "getaddrinfo", side_effect=AssertionError("unexpected resolution")):
                        result = await probe(Address(value, "ipv6"), 443, 5, connector)
                self.assertEqual(result.status, "connected")
                sock, actual_endpoint = connector.call_args.args
                self.assertEqual(sock.family, socket.AF_INET6)
                self.assertEqual(sock.fileno(), -1)
                self.assertEqual(actual_endpoint, endpoint)

    async def test_os_errors_are_classified_and_close_socket(self):
        for number, status in (
            (errno.ECONNREFUSED, "refused"), (errno.ETIMEDOUT, "timeout"),
            (errno.EHOSTUNREACH, "unreachable"), (errno.EACCES, "error"),
        ):
            sockets = []

            async def failing(sock, endpoint):
                sockets.append(sock)
                raise OSError(number, "controlled failure")

            with self.subTest(number=number):
                result = await probe(Address("127.0.0.1", "ipv4"), 80, 5, failing)
                self.assertEqual(result.status, status)
                self.assertEqual(sockets[0].fileno(), -1)

    async def test_default_connector_does_not_resolve_scoped_ipv6(self):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", side_effect=AssertionError("unexpected resolution")) as resolver:
            with patch.object(socket.socket, "connect", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "refused")) as connect:
                result = await probe(Address("fe80::1%7", "ipv6"), 443, 5)
        self.assertEqual(result.status, "refused")
        resolver.assert_not_called()
        connect.assert_called_once_with(("fe80::1", 443, 0, 7))
