#!/usr/bin/env python3

"""Test import/export error conditions."""

import os

from testlib import check, cmd, util
from testlib.log import log
from testlib.const import RUN_ACCESS_CHECKS
from testlib.proc import Tinc
from testlib.test import Test

SEPARATOR = f"#{'-' * 63}#"

MULTI_HOST = f"""
Name = node0
Address = sun
{SEPARATOR}
Name = node1
Address = moon
{SEPARATOR}
""".strip()

MAX_PATH = 255 if os.name == "nt" else os.pathconf("/", "PC_PATH_MAX")
LONG_NAME = MAX_PATH * "x"


def init(ctx: Test) -> Tinc:
    """Initialize a node."""
    return ctx.node(init="set AutoConnect no")


def test_import(foo: Tinc) -> None:
    """Run tests for command 'import'."""

    _, err = foo.cmd("import", "foo", code=1)
    check.is_in("Too many arguments", err)

    _, err = foo.cmd("import", code=1)
    check.is_in("No host configuration files imported", err)

    for prefix in "fred", "Name fred", "name = fred", "name=fred":
        log.info("testing prefix '%s'", prefix)
        _, err = foo.cmd("import", stdin=prefix, code=1)
        check.is_in("Junk at the beginning", err)

    _, err = foo.cmd("import", stdin="Name = !@#", code=1)
    check.is_in("Invalid Name in input", err)

    _, err = foo.cmd("import", stdin=f"Name = {LONG_NAME}", code=1)
    check.is_in("Filename too long", err)

    log.info("make sure no address for imported nodes is present")
    for node in "node0", "node1":
        foo.cmd("get", f"{node}.Address", code=1)

    _, err = foo.cmd("import", stdin=MULTI_HOST)
    check.is_in("Imported 2 host configuration files", err)

    log.info("check imported nodes addresses")
    check.equals("sun", cmd.get(foo, "node0.Address"))
    check.equals("moon", cmd.get(foo, "node1.Address"))

    _, err = foo.cmd("import", stdin="Name = node0", code=1)
    check.is_in("node0 already exists", err)

    if RUN_ACCESS_CHECKS:
        log.info("import to inaccessible hosts subdirectory")
        os.chmod(foo.sub("hosts"), 0)
        _, err = foo.cmd("import", stdin="Name = vinny", code=1)
        check.is_in("Error creating configuration", err)


def test_export(foo: Tinc) -> None:
    """Run tests for command 'export'."""

    _, err = foo.cmd("export", "foo", code=1)
    check.is_in("Too many arguments", err)

    os.remove(foo.sub(f"hosts/{foo}"))
    _, err = foo.cmd("export", code=1)
    check.is_in("Could not open configuration", err)

    util.write_text(foo.sub("tinc.conf"), "")
    _, err = foo.cmd("export", code=1)
    check.is_in("Could not find Name", err)

    os.remove(foo.sub("tinc.conf"))
    _, err = foo.cmd("export", code=1)
    check.is_in("Could not open", err)


def test_exchange(foo: Tinc) -> None:
    """Run tests for command 'exchange'."""

    log.info("make sure exchange does not import if export fails")
    util.write_text(foo.sub("tinc.conf"), "")
    host_foo = "Name = foo\nAddress = 1.1.1.1"
    _, err = foo.cmd("exchange", stdin=host_foo, code=1)
    assert "Imported" not in err


def test_exchange_all(foo: Tinc) -> None:
    """Run tests for command 'exchange'."""

    log.info("make sure exchange-all does not import if export fails")
    host_bar = foo.sub("hosts/bar")
    util.write_text(host_bar, "")
    os.chmod(host_bar, 0)
    host_foo = "Name = foo\nAddress = 1.1.1.1"
    _, err = foo.cmd("exchange-all", stdin=host_foo, code=1)
    assert "Imported" not in err


def test_export_all(foo: Tinc) -> None:
    """Run tests for command 'export-all'."""

    _, err = foo.cmd("export-all", "foo", code=1)
    check.is_in("Too many arguments", err)

    host_foo = foo.sub("hosts/foo")
    util.write_text(host_foo, "Name = foo")
    os.chmod(host_foo, 0)

    host_bar = foo.sub("hosts/bar")
    util.write_text(host_bar, "Host = bar\nAddress = 1.1.1.1")

    host_invalid = foo.sub("hosts/xi-Eb-Vx-k3")
    util.write_text(host_invalid, "Host = invalid")

    out, err = foo.cmd("export-all", code=1)
    check.is_in("Could not open configuration", err)

    log.info("checking bad node name in export")
    assert "xi-Eb-Vx-k3" not in out

    for want in "Host = bar", "Address = 1.1.1.1", SEPARATOR:
        check.is_in(want, out)

    log.info("verify that separators are used on separate lines")
    lines = out.splitlines()
    separators = list(filter(lambda line: line == SEPARATOR, lines))
    if len(separators) != 2:
        log.info("unexpected number of separators: %s", lines)
        assert False

    if RUN_ACCESS_CHECKS:
        os.chmod(foo.sub("hosts"), 0)
        _, err = foo.cmd("export-all", code=1)
        check.is_in("Could not open host configuration", err)


with Test("test 'import' command") as context:
    test_import(init(context))

with Test("test 'export' command") as context:
    test_export(init(context))

with Test("test 'exchange' command") as context:
    test_exchange(init(context))

if RUN_ACCESS_CHECKS:
    with Test("test 'exchange-all' command") as context:
        test_exchange_all(init(context))

    with Test("test 'export-all' command") as context:
        test_export_all(init(context))
