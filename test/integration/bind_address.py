#!/usr/bin/env python3

"""Test binding to interfaces and addresses."""

import json
import socket
import subprocess as subp
import sys
import typing as T

from testlib import check, util
from testlib.const import EXIT_SKIP
from testlib.log import log
from testlib.test import Test

util.require_command("ss", "-nlup")
util.require_command("ip", "--json", "addr")


def connect_tcp(address: str, port: int) -> None:
    """Check that a TCP connection to (address, port) works."""

    family = socket.AF_INET if "." in address else socket.AF_INET6

    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.connect((address, port))


def get_interfaces() -> T.List[T.Tuple[str, T.List[str]]]:
    """Get a list of network interfaces with assigned addresses."""

    output = subp.run(
        ["ip", "--json", "addr"], check=True, encoding="utf-8", stdout=subp.PIPE
    ).stdout

    result: T.List[T.Tuple[str, T.List[str]]] = []

    for line in json.loads(output):
        if not "UP" in line["flags"]:
            continue
        local: T.List[str] = []
        for addr in line["addr_info"]:
            if addr["family"] in ("inet", "inet6"):
                local.append(addr["local"])
        if local:
            result.append((line["ifname"], local))

    return result


INTERFACES = get_interfaces()


def get_udp_listen(pid: int) -> T.List[str]:
    """Get a list of the currently listening UDP sockets."""

    listen = subp.run(["ss", "-nlup"], check=True, stdout=subp.PIPE, encoding="utf-8")
    addresses: T.List[str] = []

    for line in listen.stdout.splitlines():
        if f"pid={pid}," in line:
            _, _, _, addr, _ = line.split(maxsplit=4)
            addresses.append(addr)

    return addresses


def test_bind_interface(ctx: Test) -> None:
    """Test BindToInterface."""

    devname, addresses = INTERFACES[0]
    log.info("using interface %s, addresses (%s)", devname, addresses)

    init = f"""
        set BindToInterface {devname}
        set LogLevel 5
    """
    foo = ctx.node(init=init)
    foo.start()

    log.info("check that tincd opened UDP sockets")
    listen = get_udp_listen(foo.pid)
    check.is_in(f"%{devname}:{foo.port}", *listen)

    log.info("check TCP sockets")
    for addr in addresses:
        connect_tcp(addr, foo.port)


def test_bind_address(ctx: Test, kind: str) -> None:
    """Test BindToAddress or ListenAddress."""

    _, addresses = INTERFACES[0]

    log.info("create and start tincd node")
    foo = ctx.node(init="set LogLevel 10")
    for addr in addresses:
        foo.cmd("add", kind, addr)
    foo.start()

    log.info("check for correct log message")
    for addr in addresses:
        check.in_file(foo.sub("log"), f"Listening on {addr}")

    log.info("test TCP connections")
    for addr in addresses:
        connect_tcp(addr, foo.port)

    log.info("check that tincd opened UDP sockets")
    listen = get_udp_listen(foo.pid)
    for addr in addresses:
        check.is_in(addr, *listen)
        check.is_in(f":{foo.port}", *listen)
    check.equals(len(addresses), len(listen))


if not INTERFACES:
    log.info("interface list is empty, skipping test")
    sys.exit(EXIT_SKIP)

with Test("test ListenAddress") as context:
    test_bind_address(context, "ListenAddress")

with Test("test BindToAddress") as context:
    test_bind_address(context, "BindToAddress")

with Test("test BindToInterface") as context:
    test_bind_interface(context)
