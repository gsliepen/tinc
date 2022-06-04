#!/usr/bin/env python3

"""Test binding to ports on localhost."""

import socket
import sys
import typing as T

from testlib import check, util
from testlib.const import EXIT_SKIP
from testlib.log import log
from testlib.proc import Script
from testlib.test import Test

# Call to close opened port
Closer = T.Callable[[], None]


def bind_random_port() -> T.Tuple[T.Optional[int], Closer]:
    """Bind to random port and return it, keeping the bind."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        _, port = sock.getsockname()
        return port, sock.close
    except OSError:
        return None, sys.exit


def test_bind_port(ctx: Test, ok_ports: T.List[int], bad_ports: T.List[int]) -> None:
    """Test binding to ports on localhost."""

    foo = ctx.node(init="set LogLevel 1")
    foo.add_script(Script.TINC_UP)
    foo.add_script(Script.TINC_DOWN)
    log_path = foo.sub("log")

    if ok_ports:
        log.info("check that tincd successfully binds to %s", ok_ports)

        for port in ok_ports:
            foo.cmd("add", "BindToAddress", f"127.0.0.1 {port}")

        proc = foo.tincd("-D")
        foo[Script.TINC_UP].wait()
        foo.cmd("stop")
        foo[Script.TINC_DOWN].wait()
        check.success(proc.wait())

        foo_log = util.read_text(log_path)

        for port in ok_ports:
            check.is_in(f"Listening on 127.0.0.1 port {port}", foo_log)

    if bad_ports:
        log.info("check that tincd fails to bind to %s", bad_ports)

        for port in bad_ports:
            foo.cmd("add", "BindToAddress", f"127.0.0.1 {port}")

        util.remove_file(log_path)
        proc = foo.tincd("-D")

        # Flush logs to the log file
        if ok_ports:
            foo[Script.TINC_UP].wait()
            foo.cmd("stop")
            foo[Script.TINC_DOWN].wait()
            check.success(proc.wait())
        else:
            check.failure(proc.wait())

        foo_log = util.read_text(log_path)

        for port in bad_ports:
            check.is_in(f"Can't bind to 127.0.0.1 port {port}", foo_log)

        if not ok_ports:
            check.is_in("Unable to create any listening socket", foo_log)


port0, close0 = bind_random_port()
port1, close1 = bind_random_port()

if not port0 or not port1:
    log.info("could not bind ports, skipping test")
    sys.exit(EXIT_SKIP)

with Test("test binding with both ports unavailable") as context:
    test_bind_port(context, [], [port0, port1])

with Test("test binding to one free and one unavailable port") as context:
    close0()
    test_bind_port(context, [port0], [port1])

with Test("test binding to two free ports") as context:
    close1()
    test_bind_port(context, [port0, port1], [])
