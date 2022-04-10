#!/usr/bin/env python3

"""Check that legacy protocol works with different cryptographic algorithms."""

import typing as T

from testlib.test import Test
from testlib.proc import Tinc
from testlib.log import log
from testlib import cmd, check


def init(ctx: Test, digest: str, cipher: str) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar = ctx.node(), ctx.node()

    stdin = f"""
        init {foo}
        set Port 0
        set DeviceType dummy
        set Address localhost
        set ExperimentalProtocol no
        set Digest {digest}
        set Cipher {cipher}
    """
    foo.cmd(stdin=stdin)
    foo.start()

    stdin = f"""
        init {bar}
        set Port 0
        set DeviceType dummy
        set Address localhost
        set ExperimentalProtocol no
        set Digest {digest}
        set Cipher {cipher}
    """
    bar.cmd(stdin=stdin)

    foo.add_script(bar.script_up)
    bar.add_script(foo.script_up)

    cmd.exchange(foo, bar)
    bar.cmd("add", "ConnectTo", foo.name)
    bar.cmd("start")

    return foo, bar


def test(foo: Tinc, bar: Tinc) -> None:
    """Run tests on algorithm pair."""
    log.info("waiting for bar to come up")
    foo[bar.script_up].wait()

    log.info("waiting for foo to come up")
    bar[foo.script_up].wait()

    log.info("checking node reachability")
    stdout, _ = foo.cmd("info", bar.name)
    check.is_in("reachable", stdout)


for alg_digest in "none", "sha256", "sha512":
    for alg_cipher in "none", "aes-256-cbc":
        with Test("compression") as context:
            node0, node1 = init(context, alg_digest, alg_cipher)
            test(node0, node1)
