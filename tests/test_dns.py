import asyncio
import socket
import unittest

from routescope.dns import resolve


def record(family, address):
    endpoint = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
    return (family, socket.SOCK_STREAM, 0, "", endpoint)


class DnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_deduplicates_and_filters_family(self):
        async def resolver(*args, **kwargs):
            return [
                record(socket.AF_INET6, "::1"),
                record(socket.AF_INET, "127.0.0.1"),
                record(socket.AF_INET, "127.0.0.1"),
            ]

        result = await resolve("example.invalid", "ipv4", 0.1, resolver)
        self.assertEqual(result.status, "resolved")
        self.assertEqual([(a.value, a.family) for a in result.addresses], [("127.0.0.1", "ipv4")])

    async def test_literal_skips_resolver_and_checks_family(self):
        async def forbidden(*args, **kwargs):
            self.fail("resolver should not run for numeric addresses")

        result = await resolve("127.0.0.1", "both", 0.1, forbidden)
        self.assertEqual(result.status, "literal")
        self.assertEqual(result.addresses[0].value, "127.0.0.1")
        mismatch = await resolve("::1", "ipv4", 0.1, forbidden)
        self.assertEqual(mismatch.status, "error")
        for host in ("::1", "fe80::1%7", "fe80::1%test-interface"):
            with self.subTest(host=host):
                result = await resolve(host, "ipv6", 0.1, forbidden)
                self.assertEqual(result.status, "literal")
                self.assertEqual(result.addresses[0].value, host)

    async def test_error_and_timeout(self):
        async def failing(*args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, "name not known")

        async def slow(*args, **kwargs):
            await asyncio.Future()

        self.assertEqual((await resolve("bad.invalid", "both", 0.1, failing)).status, "error")
        self.assertEqual((await resolve("slow.invalid", "both", 0.001, slow)).status, "timeout")

    async def test_address_limit_is_reported(self):
        async def resolver(*args, **kwargs):
            return [record(socket.AF_INET, f"127.0.0.{i}") for i in range(1, 11)]

        result = await resolve("many.invalid", "both", 0.1, resolver)
        self.assertEqual(len(result.addresses), 8)
        self.assertTrue(result.truncated)

    async def test_both_and_ipv6_preserve_family_order(self):
        async def resolver(*args, **kwargs):
            self.assertEqual(kwargs, {"family": socket.AF_UNSPEC, "type": socket.SOCK_STREAM})
            return [record(socket.AF_INET6, "::1"), record(socket.AF_INET, "127.0.0.1"),
                    record(socket.AF_INET6, "::1")]

        for family, expected in (("both", ["::1", "127.0.0.1"]), ("ipv6", ["::1"])):
            with self.subTest(family=family):
                result = await resolve("local.invalid", family, 5, resolver)
                self.assertEqual([a.value for a in result.addresses], expected)

    async def test_ipv6_scope_is_preserved_and_deduplicated(self):
        async def resolver(*args, **kwargs):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", endpoint) for endpoint in (
                ("fe80::1", 0, 0, 7), ("fe80::1%7", 0, 0, 7), ("fe80::1", 0, 0, 8),
            )]

        result = await resolve("local.invalid", "ipv6", 5, resolver)
        self.assertEqual([a.value for a in result.addresses], ["fe80::1%7", "fe80::1%8"])

    async def test_no_matching_addresses_is_an_error(self):
        async def resolver(*args, **kwargs):
            return [record(socket.AF_INET, "127.0.0.1")]

        result = await resolve("local.invalid", "ipv6", 5, resolver)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.addresses, [])
