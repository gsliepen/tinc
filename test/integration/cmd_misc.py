#!/usr/bin/env python3

"""Test miscellaneous commands."""
import os
import typing as T

from testlib import check, cmd
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test

SUBNETS_BAR = ("10.20.30.40", "fe80::")


def configure_nodes(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Create and configure nodes."""

    log.info("initialize nodes")
    foo, bar = ctx.node(init=True), ctx.node(init=True)

    log.info("configure and start nodes")
    foo.cmd("add", "Subnet", "1.2.3.4")
    foo.add_script(Script.TINC_UP)
    foo.add_script(bar.script_up)
    foo.start()

    for sub in SUBNETS_BAR:
        bar.cmd("add", "Subnet", sub)
    bar.start()

    log.info("connect nodes")
    cmd.exchange(foo, bar)
    foo.cmd("add", "ConnectTo", bar.name)
    foo.cmd("retry")
    foo[bar.script_up].wait()

    return foo, bar


def test_version(foo: Tinc) -> None:
    """Test command 'version'."""

    log.info("test command 'version' with redundant arguments")
    _, err = foo.cmd("version", "foo", code=1)
    check.is_in("Too many arguments", err)

    log.info("test command 'version'")
    out, _ = foo.cmd("version")
    check.has_prefix(out, "tinc version ")


def test_help(foo: Tinc) -> None:
    """Test command 'help'."""

    log.info("test command 'help'")
    out, _ = foo.cmd("help")
    check.is_in("Valid options are", out)

    out, _ = foo.cmd("help", "foobar")
    check.is_in("Valid options are", out)


def test_info(foo: Tinc, bar: Tinc) -> None:
    """Test command 'info'."""

    log.info("info invalid arguments")
    _, err = foo.cmd("info", code=1)
    check.is_in("Invalid number of arguments", err)

    log.info("info unknown node")
    _, err = foo.cmd("info", "foobar", code=1)
    check.is_in("Unknown node foobar", err)

    log.info("info own node")
    out, _ = foo.cmd("info", foo.name)
    check.is_in("can reach itself", out)

    log.info("info peer node")
    out, _ = foo.cmd("info", bar.name)
    check.is_in(bar.name, out)
    for sub in SUBNETS_BAR:
        check.is_in(sub, out)

    log.info("info unknown subnet")
    for sub in "1.1.1.1", "fe82:42::":
        _, err = foo.cmd("info", sub, code=1)
        check.is_in("Unknown address", err)

    log.info("info own valid subnet")
    out, _ = foo.cmd("info", "1.2.3.4")
    check.is_in("Subnet: 1.2.3.4", out)
    check.is_in(f"Owner:  {foo}", out)

    for sub in SUBNETS_BAR:
        log.info("info peer's valid subnet %s", sub)
        out, _ = foo.cmd("info", sub)
        check.is_in(f"Subnet: {sub}", out)
        check.is_in(f"Owner:  {bar}", out)


def test_pid(foo: Tinc) -> None:
    """Test command 'pid'."""

    log.info("test pid with too many arguments")
    _, err = foo.cmd("pid", "foo", code=1)
    check.is_in("Too many arguments", err)

    log.info("test pid without arguments")
    out, _ = foo.cmd("pid")
    check.equals(foo.pid, int(out.strip()))


def test_debug(foo: Tinc) -> None:
    """Test command 'debug'."""

    for args in ("debug",), ("debug", "1", "2"):
        _, err = foo.cmd(*args, code=1)
        check.is_in("Invalid number of arguments", err)

    _, err = foo.cmd("debug", "5")
    check.is_in("new level 5", err)


def test_log(foo: Tinc) -> None:
    """Test command 'log'."""

    log.info("test with too many arguments")
    _, err = foo.cmd("log", "foo", "bar", code=1)
    check.is_in("Too many arguments", err)

    log.info("test correct call")
    log_client = foo.tinc("log")
    foo.cmd("set", "LogLevel", "10")
    foo.cmd("reload")

    foo.add_script(Script.TINC_DOWN)
    foo.cmd("stop")
    foo[Script.TINC_DOWN].wait()

    out, _ = log_client.communicate()
    check.true(out)


def test_restart(foo: Tinc) -> None:
    """Test command 'restart'."""

    log.info("restart without arguments")
    foo.cmd("restart")
    foo[Script.TINC_UP].wait()

    log.info("restart with an argument")
    foo.cmd("restart", "-d3")
    foo[Script.TINC_UP].wait()

    # Checking the error message is unreliable since
    # it's provided by getopt() and differs from OS to OS.
    log.info("restart with invalid options")
    foo.cmd("restart", "--fake-invalid-option", code=1)

    log.info("restart with invalid arguments")
    _, err = foo.cmd("restart", "bad-incorrect-argument", code=1)
    check.is_in("unrecognized argument", err)


def test_shell(foo: Tinc) -> None:
    """Test shell."""

    log.info("indented comments are not ignored")
    _, err = foo.cmd(stdin=" # ", code=1)
    check.is_in("Unknown command", err)

    log.info("comments are ignored")
    _, err = foo.cmd(stdin="# this_will_fail unless comments are ignored")
    assert "this_will_fail" not in err

    log.info("inline comments are treated as arguments")
    _, err = foo.cmd(stdin="version # inline comments are not ignored", code=1)
    check.is_in("Too many arguments", err)

    log.info("check exit commands")
    for command in "exit", "quit":
        out, _ = foo.cmd(stdin=command)
        check.blank(out)


def run_tests(ctx: Test) -> None:
    """Run tests."""

    foo, bar = configure_nodes(ctx)
    test_shell(foo)
    test_version(foo)
    test_help(foo)
    test_info(foo, bar)
    test_pid(foo)
    test_debug(foo)
    test_log(foo)

    # Too unstable on Windows because of how it works with services (impossible to
    # start the service if it has been marked for deletion, but not yet deleted).
    # Since lots of things can prevent service removal (like opened task manager or
    # services.msc) the `restart` command is inherently unreliable.
    if os.name != "nt":
        test_restart(foo)


with Test("run tests") as context:
    run_tests(context)
