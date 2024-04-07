#!/usr/bin/env python3

"""Test multicast device."""

import enum
import os
import select
import socket
import struct
import time

from testlib import check
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test

MCAST_ADDR = "224.15.98.12"
PORT = 38245


class MulticastSupport(enum.Enum):
    NO = 0
    BLOCKED = 1
    YES = 2


def multicast_works() -> MulticastSupport:
    """Check if multicast is supported and works."""

    msg = b"foobar"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((MCAST_ADDR, PORT))

            req = struct.pack("=4sl", socket.inet_aton(MCAST_ADDR), socket.INADDR_ANY)
            server.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, req)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(msg, (MCAST_ADDR, PORT))

            try:
                select.select([server], [], [], 1)
                if msg == server.recv(16, socket.MSG_DONTWAIT):
                    return MulticastSupport.YES
            except OSError:
                pass

            return MulticastSupport.BLOCKED
    except OSError:
        log.info("no")
        return MulticastSupport.NO


def test_no_mcast_support(foo: Tinc) -> None:
    """Check that startup fails on systems without multicast support."""

    code = foo.tincd("-D").wait()
    check.failure(code)
    check.in_file(foo.sub("log"), f"Can't bind to {MCAST_ADDR}")


def test_rx_tx(foo: Tinc) -> None:
    """Test sending real data to a multicast device."""

    foo.start()
    packet = os.urandom(137)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        for _ in range(5):
            sent = sock.sendto(packet, (MCAST_ADDR, PORT))
            log.info("sent broken packet (%d)", sent)
            time.sleep(0.1)

    foo.add_script(Script.TINC_DOWN)
    foo.cmd("stop")
    foo[Script.TINC_DOWN].wait()

    check.in_file(foo.sub("log"), "Read packet of 137 bytes from multicast socket")


def test_device_multicast(ctx: Test) -> None:
    """Test multicast device."""

    foo = ctx.node(init=True)
    foo.cmd("set", "DeviceType", "multicast")

    log.info("check that multicast does not work without Device")
    _, err = foo.cmd("start", "-D", code=1)
    check.is_in("Device variable required for multicast socket", err)

    log.info("check that Device requires a port")
    foo.cmd("set", "Device", "localhost")
    _, err = foo.cmd("start", "-D", code=1)
    check.is_in("Port number required", err)

    log.info("check that multicast receives data")
    foo.cmd("set", "Device", f"{MCAST_ADDR} {PORT}")
    foo.cmd("set", "LogLevel", "10")

    multicast_support = multicast_works()
    if multicast_support == MulticastSupport.YES:
        log.info("multicast supported")
        test_rx_tx(foo)
    elif multicast_support == MulticastSupport.BLOCKED:
        log.info("multicast blocked")
        pass
    else:
        log.info("multicast not supported")
        test_no_mcast_support(foo)


with Test("test DeviceType = multicast") as context:
    test_device_multicast(context)
