"""Run tests with DNS and TCP restricted to loopback in the test process.

CLI subprocess tests also use only explicit loopback addresses or localhost.
"""

import ipaddress
import socket
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


def check_host(host):
    if host is None or host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise AssertionError(f"Tests must not access non-loopback host {host!r}")


def main():
    original_resolver = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def resolver(host, *args, **kwargs):
        check_host(host)
        return original_resolver(host, *args, **kwargs)

    def guarded_connect(original):
        def connect(sock, address):
            if sock.family in (socket.AF_INET, socket.AF_INET6):
                check_host(address[0])
            return original(sock, address)
        return connect

    tests = Path(__file__).resolve().parents[1] / "tests"
    with ExitStack() as stack:
        stack.enter_context(patch("socket.getaddrinfo", resolver))
        stack.enter_context(patch.object(socket.socket, "connect", guarded_connect(original_connect)))
        stack.enter_context(patch.object(socket.socket, "connect_ex", guarded_connect(original_connect_ex)))
        suite = unittest.defaultTestLoader.discover(str(tests))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
