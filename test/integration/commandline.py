#!/usr/bin/env python3

"""Test supported and unsupported commandline flags."""

import os
import signal
import subprocess as subp
import time

from testlib import check, util, path
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test
from testlib.feature import SANDBOX_LEVEL

tinc_flags = (
    (0, ("get", "name")),
    (0, ("-n", "foo", "get", "name")),
    (0, ("-nfoo", "get", "name")),
    (0, ("--net=foo", "get", "name")),
    (0, ("--net", "foo", "get", "name")),
    (0, ("-c", "conf", "-c", "conf")),
    (0, ("-n", "net", "-n", "net")),
    (0, ("--pidfile=pid", "--pidfile=pid")),
    (1, ("-n", "foo", "get", "somethingreallyunknown")),
    (1, ("--net",)),
    (1, ("--net", "get", "name")),
    (1, ("foo",)),
    (1, ("-c", "conf", "-n", "n/e\\t")),
)

tincd_flags = (
    (0, ("-D",)),
    (0, ("--no-detach",)),
    (0, ("-D", "-d")),
    (0, ("-D", "-d2")),
    (0, ("-D", "-d", "2")),
    (0, ("-D", "-n", "foo")),
    (0, ("-D", "-nfoo")),
    (0, ("-D", "--net=foo")),
    (0, ("-D", "--net", "foo")),
    (0, ("-D", "-c", ".", "-c", ".")),
    (0, ("-D", "-n", "net", "-n", "net")),
    (0, ("-D", "-n", "net", "-o", "FakeOpt=42")),
    (0, ("-D", "--logfile=log", "--logfile=log")),
    (0, ("-D", "--pidfile=pid", "--pidfile=pid")),
    (1, ("foo",)),
    (1, ("--pidfile",)),
    (1, ("--foo",)),
    (1, ("-n", "net", "-o", "Compression=")),
    (1, ("-c", "fakedir", "-n", "n/e\\t")),
)


def init(ctx: Test) -> Tinc:
    """Initialize new test nodes."""
    tinc = ctx.node()
    stdin = f"""
        init {tinc}
        set Port 0
        set Address localhost
        set DeviceType dummy
        set Sandbox {SANDBOX_LEVEL}
    """
    tinc.cmd(stdin=stdin)
    tinc.add_script(Script.TINC_UP)
    return tinc


with Test("commandline flags") as context:
    node = init(context)

    for code, flags in tincd_flags:
        COOKIE = util.random_string(10)
        server = node.tincd(*flags, env={"COOKIE": COOKIE})

        if not code:
            log.info("waiting for tincd to come up")
            env = node[Script.TINC_UP].wait().env
            check.equals(COOKIE, env["COOKIE"])

        log.info("stopping tinc")
        node.cmd("stop", code=code)

        log.info("reading tincd output")
        stdout, stderr = server.communicate()

        log.debug('got code %d, ("%s", "%s")', server.returncode, stdout, stderr)
        check.equals(code, server.returncode)

    for code, flags in tinc_flags:
        node.cmd(*flags, code=code)


def test_relative_path(ctx: Test, chroot: bool) -> None:
    """Test tincd with relative paths."""

    foo = init(ctx)

    conf_dir = os.path.realpath(foo.sub("."))
    dirname = os.path.dirname(conf_dir)
    basename = os.path.basename(conf_dir)
    log.info("using confdir %s, dirname %s, basename %s", conf_dir, dirname, basename)

    args = [
        path.TINCD_PATH,
        "-D",
        "-c",
        basename,
        "--pidfile",
        "pid",
        "--logfile",
        ".//./log",
    ]

    if chroot:
        args.append("-R")

    pidfile = os.path.join(dirname, "pid")
    util.remove_file(pidfile)

    logfile = os.path.join(dirname, "log")
    util.remove_file(logfile)

    with subp.Popen(args, stderr=subp.STDOUT, cwd=dirname) as tincd:
        foo[Script.TINC_UP].wait(10)

        log.info("pidfile and logfile must exist at expected paths")
        check.file_exists(pidfile)
        check.file_exists(logfile)

        # chrooted tincd won't be able to reopen its log since in this
        # test we put the log outside tinc's configuration directory.
        if os.name != "nt" and not chroot:
            log.info("test log file rotation")
            time.sleep(1)
            util.remove_file(logfile)
            os.kill(tincd.pid, signal.SIGHUP)
            time.sleep(1)

            log.info("pidfile and logfile must still exist")
            check.file_exists(pidfile)
            check.file_exists(logfile)

        log.info("stopping tinc through '%s'", pidfile)
        foo.cmd("--pidfile", pidfile, "stop")
        check.equals(0, tincd.wait())


with Test("relative path to tincd dir") as context:
    test_relative_path(context, chroot=False)

if os.name != "nt" and not os.getuid():
    with Test("relative path to tincd dir (chroot)") as context:
        test_relative_path(context, chroot=True)
