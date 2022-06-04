#!/usr/bin/env python3

"""Test invite/join error conditions."""

import os
import shutil

from testlib import check, util
from testlib.log import log
from testlib.const import RUN_ACCESS_CHECKS
from testlib.proc import Tinc
from testlib.test import Test

FAKE_INVITE = "localhost:65535/pVOZMJGm3MqTvTu0UnhMGb2cfuqygiu79MdnERnGYdga5v8C"


def test_invite(foo: Tinc) -> None:
    """Test successful 'invite'."""

    foo.cmd("set", "Mode", "switch")
    foo.cmd("set", "Broadcast", "mst")
    foo.start()

    log.info("test successful invitation")
    out, _ = foo.cmd("invite", "quux")
    check.is_in(f"localhost:{foo.port}/", out)

    for filename in os.listdir(foo.sub("invitations")):
        content = util.read_text(foo.sub(f"invitations/{filename}"))
        if filename == "ed25519_key.priv":
            check.is_in("-----BEGIN ED25519 PRIVATE KEY-----", content)
        else:
            check.is_in("Broadcast = mst", content)
            check.is_in("Mode = switch", content)
            check.is_in("Address = localhost", content)
            check.is_in("Name = quux", content)
            check.is_in(f"NetName = {foo}", content)
            check.is_in(f"ConnectTo = {foo}", content)


def test_invite_errors(foo: Tinc) -> None:
    """Test invite error conditions."""

    log.info("invite node with tincd stopped")
    _, err = foo.cmd("invite", "foobar", code=1)
    check.is_in("Could not open pid file", err)

    log.info("start node %s", foo)
    foo.start()

    log.info("invite without arguments")
    _, err = foo.cmd("invite", code=1)
    check.is_in("Not enough arguments", err)

    log.info("invite with too many arguments")
    _, err = foo.cmd("invite", "foo", "bar", code=1)
    check.is_in("Too many arguments", err)

    log.info("invite with invalid name")
    _, err = foo.cmd("invite", "!@#", code=1)
    check.is_in("Invalid name for node", err)

    log.info("invite existing node")
    _, err = foo.cmd("invite", foo.name, code=1)
    check.is_in("already exists", err)

    if RUN_ACCESS_CHECKS:
        log.info("bad permissions on invitations are fixed")
        invites = foo.sub("invitations")
        os.chmod(invites, 0)
        out, _ = foo.cmd("invite", "foobar")
        check.has_prefix(out, "localhost:")

        log.info("invitations directory is created with bad permissions on parent")
        shutil.rmtree(invites)
        os.chmod(foo.work_dir, 0o500)
        out, _ = foo.cmd("invite", "foobar")
        check.has_prefix(out, "localhost:")
        check.true(os.access(invites, os.W_OK))

        log.info("fully block access to configuration directory")
        work_dir = foo.sub("test_no_access")
        os.mkdir(work_dir, mode=0)
        _, err = foo.cmd("-c", work_dir, "invite", "foobar", code=1)
        check.is_in("Could not open", err)


def test_join_errors(foo: Tinc) -> None:
    """Test join error conditions."""

    log.info("try joining with redundant arguments")
    _, err = foo.cmd("join", "bar", "quux", code=1)
    check.is_in("Too many arguments", err)

    log.info("try joining with existing configuration")
    _, err = foo.cmd("join", FAKE_INVITE, code=1)
    check.is_in("already exists", err)

    log.info("try running without an invite URL")
    work_dir = foo.sub("test_no_invite")
    join = foo.tinc("-c", work_dir, "join")
    _, err = join.communicate(input="")
    check.equals(1, join.returncode)
    check.is_in("Error while reading", err)

    log.info("try using an invalid invite")
    work_dir = foo.sub("test_invalid_invite")
    _, err = foo.cmd("-c", work_dir, "join", FAKE_INVITE, code=1)
    check.is_in("Could not connect to", err)

    if RUN_ACCESS_CHECKS:
        log.info("bad permissions on configuration directory are fixed")
        work_dir = foo.sub("wd_access_test")
        os.mkdir(work_dir, mode=400)
        _, err = foo.cmd("-c", work_dir, "join", FAKE_INVITE, code=1)
        check.is_in("Could not connect to", err)
        check.true(os.access(work_dir, mode=os.W_OK))


with Test("run invite success tests") as context:
    test_invite(context.node(init=True))

with Test("run invite error tests") as context:
    test_invite_errors(context.node(init=True))

with Test("run join tests") as context:
    test_join_errors(context.node(init=True))
