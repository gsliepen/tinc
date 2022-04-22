#!/usr/bin/env python3

"""Test tinc protocol security."""

import asyncio
import typing as T

from testlib import check
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test
from testlib.feature import SANDBOX_LEVEL

TIMEOUT = 2


async def recv(read: asyncio.StreamReader, out: T.List[bytes]) -> None:
    """Receive data until connection is closed."""
    while not read.at_eof():
        rec = await read.read(1)
        out.append(rec)


async def send(port: int, buf: str, delay: float = 0) -> bytes:
    """Send data and receive response."""
    raw = f"{buf}\n".encode("utf-8")
    read, write = await asyncio.open_connection(host="localhost", port=port)

    if delay:
        await asyncio.sleep(delay)

    received: T.List[bytes] = []
    try:
        write.write(raw)
        await asyncio.wait_for(recv(read, received), timeout=1)
    except asyncio.TimeoutError:
        log.info('received: "%s"', received)
        return b"".join(received)

    raise RuntimeError("test should not have reached this line")


async def test_id_timeout(foo: Tinc) -> None:
    """Test that peer does not send its ID before us."""
    log.info("no ID sent by peer if we don't send ID before the timeout")
    data = await send(foo.port, "0 bar 17.7", delay=TIMEOUT * 1.5)
    check.false(data)


async def test_tarpitted(foo: Tinc) -> None:
    """Test that peer sends its ID if we send first and are in tarpit."""
    log.info("ID sent if initiator sends first, but still tarpitted")
    data = await send(foo.port, "0 bar 17.7")
    check.has_prefix(data, f"0 {foo} 17.7".encode("utf-8"))


async def test_invalid_id_own(foo: Tinc) -> None:
    """Test that peer does not accept its own ID."""
    log.info("own ID not allowed")
    data = await send(foo.port, f"0 {foo} 17.7")
    check.false(data)


async def test_invalid_id_unknown(foo: Tinc) -> None:
    """Test that peer does not accept unknown ID."""
    log.info("no unknown IDs allowed")
    data = await send(foo.port, "0 baz 17.7")
    check.false(data)


async def test_null_metakey(foo: Tinc) -> None:
    """Test that NULL metakey is not accepted."""
    null_metakey = f"""
0 {foo} 17.0\
1 0 672 0 0 834188619F4D943FD0F4B1336F428BD4AC06171FEABA66BD2356BC9593F0ECD643F\
0E4B748C670D7750DFDE75DC9F1D8F65AB1026F5ED2A176466FBA4167CC567A2085ABD070C1545B\
180BDA86020E275EA9335F509C57786F4ED2378EFFF331869B856DDE1C05C461E4EECAF0E2FB97A\
F77B7BC2AD1B34C12992E45F5D1254BBF0C3FB224ABB3E8859594A83B6CA393ED81ECAC9221CE6B\
C71A727BCAD87DD80FC0834B87BADB5CB8FD3F08BEF90115A8DF1923D7CD9529729F27E1B8ABD83\
C4CF8818AE10257162E0057A658E265610B71F9BA4B365A20C70578FAC65B51B91100392171BA12\
A440A5E93C4AA62E0C9B6FC9B68F953514AAA7831B4B2C31C4
""".strip()

    log.info("no NULL METAKEY allowed")
    data = await send(foo.port, null_metakey)
    check.false(data)


def init(ctx: Test) -> Tinc:
    """Initialize new test nodes."""
    foo = ctx.node()

    stdin = f"""
        init {foo}
        set Port 0
        set DeviceType dummy
        set Address localhost
        set PingTimeout {TIMEOUT}
        set AutoConnect no
        set Subnet 10.96.96.1
        set Sandbox {SANDBOX_LEVEL}
    """
    foo.cmd(stdin=stdin)

    foo.add_script(Script.SUBNET_UP)
    foo.start()
    foo[Script.SUBNET_UP].wait()

    return foo


async def run_tests(ctx: Test) -> None:
    """Run all tests."""
    foo = init(ctx)

    log.info("getting into tarpit")
    await test_id_timeout(foo)

    log.info("starting other tests")
    await asyncio.gather(
        test_invalid_id_own(foo),
        test_invalid_id_unknown(foo),
        test_null_metakey(foo),
    )


loop = asyncio.get_event_loop()

with Test("security") as context:
    loop.run_until_complete(run_tests(context))
