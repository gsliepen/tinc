#!/usr/bin/env python3

"""Test FD device support."""

import array
import socket
import tempfile
import threading
import time

from testlib import check
from testlib.log import log
from testlib.test import Test
from testlib.proc import Script

JUNK_FRAME = b"\xFF" * 80


def start_fd_server(unix: socket.socket, payload: bytes, file_desc: int) -> None:
    """Start UNIX socket server and then the FD to the first connected client."""

    def send_fd() -> None:
        conn, _ = unix.accept()
        with conn:
            log.info("accepted connection %s", conn)
            ancillary = array.array("i", [file_desc])
            conn.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, ancillary)])

    threading.Thread(target=send_fd).start()


def test_device_fd(ctx: Test) -> None:
    """Test some FD device error conditions."""

    foo = ctx.node(init="set DeviceType fd")

    log.info("test with empty Device")
    _, err = foo.cmd("start", code=1)
    check.is_in("Could not read device", err)

    log.info("test with too long UNIX socket path")
    device = "x" * 110
    _, err = foo.cmd("start", "-o", f"Device={device}", code=1)
    check.is_in("Unix socket path too long", err)

    foo.cmd("set", "Device", "/dev/null")

    log.info("check that Mode=switch fails")
    _, err = foo.cmd("start", "-o", "Mode=switch", code=1)
    check.is_in("Switch mode not supported", err)

    log.info("test with incorrect Device")
    _, err = foo.cmd("start", code=1)
    check.is_in("Receiving fd from Unix socket", err)
    check.is_in("Could not connect to Unix socket", err)

    log.info("test with invalid FD")
    _, err = foo.cmd("start", "-o", "Device=-1", code=1)
    check.is_in("Could not open", err)

    log.info("create a UNIX socket to transfer FD")
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_path = tempfile.mktemp()
    unix.bind(unix_path)
    unix.listen(1)

    foo.cmd("set", "Device", unix_path)
    myself, him = socket.socketpair(socket.AF_UNIX)

    log.info("start with empty data")
    start_fd_server(unix, b"", him.fileno())
    _, err = foo.cmd("start", "-o", f"Device={unix_path}", code=1)
    check.is_in("Could not read from unix socket", err)

    foo_log = foo.sub("log")
    foo.add_script(Script.TINC_UP)

    log.info("start with correct amount of data")
    start_fd_server(unix, b" ", him.fileno())

    log.info("wait for tincd to connect")
    _, err = foo.cmd("start", "-o", f"Device={unix_path}", "--logfile", foo_log, "-d10")
    foo[Script.TINC_UP].wait()
    check.is_in("adapter set up", err)

    log.info("send junk data and make sure tincd receives it")
    for _ in range(10):
        myself.send(JUNK_FRAME)
        time.sleep(0.1)

    foo.add_script(Script.TINC_DOWN)
    foo.cmd("stop")
    foo[Script.TINC_DOWN].wait()

    check.in_file(foo_log, "Unknown IP version while reading packet from fd/")


with Test("test FD device") as context:
    test_device_fd(context)
