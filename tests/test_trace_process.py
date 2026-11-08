"""Real subprocess lifecycle tests with an inert replacement for traceroute."""

import asyncio
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from routescope.models import Address
from routescope.trace import trace_address
from routescope.trace_models import TraceOptions


TOOL = r'''
import json
import os
import signal
import sys
import time
from pathlib import Path

record = os.environ.get("TRACE_TEST_RECORD")
if record:
    temporary = Path(record + ".tmp")
    temporary.write_text(json.dumps({"args": sys.argv[1:], "pid": os.getpid(), "locale": os.environ.get("LC_ALL")}))
    temporary.replace(record)
mode = os.environ.get("TRACE_TEST_MODE", "normal")
host = sys.argv[-1]
if mode == "stall":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    print("1 *", flush=True)
    while True:
        time.sleep(1)
elif mode == "error":
    print("traceroute: permission denied", file=sys.stderr)
    sys.exit(1)
elif mode == "malformed":
    print("unexpected incompatible output")
elif mode == "icmp":
    print("1 " + host + " 0.125 ms !H")
elif mode == "gap":
    print("1 *\n2 " + host + " 0.125 ms")
elif host == "127.0.0.2":
    print("1 *")
else:
    print("1 " + host + " 0.125 ms")
'''


class TraceProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="routescope-trace-tests-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ("traceroute", "traceroute6"):
            script = self.root / name
            script.write_text(f"#!{sys.executable}\n" + TOOL)
            script.chmod(0o755)
        self.record = self.root / "record.json"
        self.env = {"PATH": str(self.root), "TRACE_TEST_RECORD": str(self.record), "TRACE_TEST_MODE": "normal"}
        environment_patch = patch.dict(os.environ, self.env)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        self.options = TraceOptions(("127.0.0.1",), max_hops=1, timeout_s=1)

    def assert_reaped(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    async def wait_for_record(self):
        async def wait():
            while not self.record.exists():
                await asyncio.sleep(0.01)
        await asyncio.wait_for(wait(), 5)
        return json.loads(self.record.read_text())

    async def test_numeric_destination_locale_result_and_reaping(self):
        for platform in ("darwin", "linux"):
            for host, family in (("127.0.0.1", "ipv4"), ("::1", "ipv6")):
                with self.subTest(platform=platform, family=family), patch("routescope.trace.sys.platform", platform):
                    result = await trace_address(Address(host, family), self.options)
                    self.assertEqual(result.status, "reached", result.error)
                    self.assertEqual(result.hops[0].probes[0].rtt_ms, 0.125)
                    self.assertGreater(result.duration_ms, 0)
                    self.assertEqual(result.returncode, 0)
                    record = json.loads(self.record.read_text())
                    self.assertEqual(record["args"][-1], host)
                    self.assertEqual(record["locale"], "C")
                    self.assert_reaped(record["pid"])

    async def test_incomplete_errors_and_unsupported_output(self):
        result = await trace_address(Address("127.0.0.2", "ipv4"), self.options)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.hops[0].probes[0].status, "no_response")
        for mode, message in (("error", "permission denied"), ("malformed", "unrecognized")):
            with self.subTest(mode=mode), patch.dict(os.environ, {"TRACE_TEST_MODE": mode}):
                result = await trace_address(Address("127.0.0.1", "ipv4"), self.options)
                self.assertEqual(result.status, "error")
                self.assertIn(message, result.error)

    async def test_destination_icmp_error_and_silent_intermediate_hop(self):
        with patch.dict(os.environ, {"TRACE_TEST_MODE": "icmp"}):
            result = await trace_address(Address("127.0.0.1", "ipv4"), self.options)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.hops[0].probes[0].status, "error")
        self.assertEqual(result.hops[0].probes[0].annotation, "!H")
        with patch.dict(os.environ, {"TRACE_TEST_MODE": "gap"}):
            result = await trace_address(Address("127.0.0.1", "ipv4"), TraceOptions(("127.0.0.1",), max_hops=2))
        self.assertEqual(result.status, "reached")
        self.assertEqual(result.hops[0].probes[0].status, "no_response")

    async def test_deadline_preserves_hops_and_kills_uncooperative_child(self):
        with patch.dict(os.environ, {"TRACE_TEST_MODE": "stall"}), patch("routescope.trace.process_deadline", return_value=1):
            result = await trace_address(Address("127.0.0.1", "ipv4"), self.options)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.hops[0].probes[0].status, "no_response")
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assert_reaped(json.loads(self.record.read_text())["pid"])

    async def test_cancellation_kills_and_reaps_child(self):
        with patch.dict(os.environ, {"TRACE_TEST_MODE": "stall"}):
            task = asyncio.create_task(trace_address(Address("127.0.0.1", "ipv4"), self.options))
            try:
                record = await self.wait_for_record()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assert_reaped(record["pid"])
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    async def test_cancellation_during_spawn_recovers_child_ownership(self):
        original_spawn = asyncio.create_subprocess_exec
        spawned = asyncio.Event()
        deliver = asyncio.Event()

        async def delayed_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            spawned.set()
            await deliver.wait()
            return process

        with patch.dict(os.environ, {"TRACE_TEST_MODE": "stall"}):
            with patch("routescope.trace.asyncio.create_subprocess_exec", side_effect=delayed_spawn):
                task = asyncio.create_task(trace_address(Address("127.0.0.1", "ipv4"), self.options))
                try:
                    await asyncio.wait_for(spawned.wait(), 5)
                    record = await self.wait_for_record()
                    task.cancel()
                    deliver.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assert_reaped(record["pid"])
                finally:
                    deliver.set()
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)

    async def test_installed_entrypoints_json_text_exit_codes_and_ctrl_c(self):
        script = Path(sys.executable).with_name("routescope")
        self.assertTrue(script.is_file())
        for entrypoint in ((sys.executable, "-I", "-W", "error", "-m", "routescope"), (str(script),)):
            for hosts, status, code in ((["127.0.0.1"], "ok", 0), (["127.0.0.2"], "failed", 1),
                                       (["127.0.0.2", "127.0.0.1"], "partial", 1)):
                for output in ("json", "text"):
                    result = await self.run_cli(entrypoint, ["trace", *hosts, "--max-hops", "1", "--format", output])
                    self.assertEqual(result[0], code, result)
                    self.assertEqual(result[2], "")
                    if output == "json":
                        doc = json.loads(result[1])
                        self.assertEqual(doc["command"], "trace")
                        self.assertEqual(doc["schema_version"], 1)
                        self.assertEqual(doc["status"], status)
                        self.assertEqual([t["host"] for t in doc["targets"]], hosts)
                    else:
                        self.assertIn(f"RouteScope trace: {status}", result[1])
                        self.assertIn("not proof", result[1])
            result = await self.run_cli(entrypoint, ["trace", "127.0.0.1", "--probes", "4"])
            self.assertEqual(result[0], 2)
            self.assertEqual(result[1], "")
            with patch.dict(os.environ, {"TRACE_TEST_MODE": "stall"}):
                self.record.unlink(missing_ok=True)
                result = await self.run_cli(entrypoint, ["trace", "127.0.0.1", "--format", "json"], interrupt=True)
            self.assertEqual(result, (130, "", "Interrupted\n"))
            self.assert_reaped(json.loads(self.record.read_text())["pid"])

    async def run_cli(self, entrypoint, args, interrupt=False):
        process = await asyncio.create_subprocess_exec(
            *entrypoint, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            if interrupt:
                await self.wait_for_record()
                process.send_signal(signal.SIGINT)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
            return process.returncode, stdout.decode(), stderr.decode()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
