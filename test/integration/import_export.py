#!/usr/bin/env python3

"""Test peer information import and export."""

import typing as T

from testlib import check, cmd
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test


def init(ctx: Test) -> T.Tuple[Tinc, Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar, baz = ctx.node(), ctx.node(), ctx.node()

    log.info("configure %s", foo.name)
    stdin = f"""
        init {foo}
        set Port 0
        set Address localhost
        set DeviceType dummy
    """
    foo.cmd(stdin=stdin)

    log.info("configure %s", bar.name)
    stdin = f"""
        init {bar}
        set Port 0
        set Address localhost
        set DeviceType dummy
    """
    bar.cmd(stdin=stdin)

    log.info("configure %s", baz.name)
    stdin = f"""
        init {baz}
        set Port 0
        set Address localhost
        set DeviceType dummy
    """
    baz.cmd(stdin=stdin)

    return foo, bar, baz


def run_tests(ctx: Test) -> None:
    """Run all tests."""
    foo, bar, baz = init(ctx)

    tinc_up = f"""
    bar, baz = Tinc('{bar}'), Tinc('{baz}')
    bar.cmd('add', 'ConnectTo', this.name)
    baz.cmd('add', 'ConnectTo', this.name)
    """
    foo.add_script(Script.TINC_UP, tinc_up)
    foo.start()

    log.info("run exchange")
    cmd.exchange(foo, bar)

    log.info("run exchange with export-all")
    cmd.exchange(foo, baz, export_all=True)

    log.info("run exchange-all")
    out, err = foo.cmd("exchange-all", code=1)
    check.is_in("No host configuration files imported", err)

    log.info("run import")
    bar.cmd("import", stdin=out)

    for first, second in (
        (foo.sub("hosts", foo.name), bar.sub("hosts", foo.name)),
        (foo.sub("hosts", foo.name), baz.sub("hosts", foo.name)),
        (foo.sub("hosts", bar.name), bar.sub("hosts", bar.name)),
        (foo.sub("hosts", bar.name), baz.sub("hosts", bar.name)),
        (foo.sub("hosts", baz.name), bar.sub("hosts", baz.name)),
        (foo.sub("hosts", baz.name), baz.sub("hosts", baz.name)),
    ):
        log.info("comparing configs %s and %s", first, second)
        check.files_eq(first, second)

    log.info("create %s scripts", foo)
    foo.add_script(bar.script_up)
    foo.add_script(baz.script_up)

    log.info("start nodes")
    bar.cmd("start")
    baz.cmd("start")

    log.info("wait for up scripts")
    foo[bar.script_up].wait()
    foo[baz.script_up].wait()

    for tinc in foo, bar, baz:
        check.nodes(tinc, 3)


with Test("import-export") as context:
    run_tests(context)
