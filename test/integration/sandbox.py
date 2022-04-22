#!/usr/bin/env python3

"""Test that tincd works through proxies."""

import os
import time

from testlib import check, cmd, path, util
from testlib.proc import Tinc, Script
from testlib.test import Test
from testlib.log import log
from testlib.feature import HAVE_SANDBOX


def init(ctx: Test, level: str) -> Tinc:
    """Create a new tinc node."""

    node = ctx.node()

    stdin = f"""
        init {node}
        set Address 127.0.0.1
        set Port 0
        set DeviceType dummy
        set Sandbox {level}
    """
    node.cmd(stdin=stdin)

    return node


def test_scripts_work(ctx: Test, level: str) -> None:
    """Test that scripts work under the sandbox level."""
    foo = init(ctx, level)
    foo.cmd("set", "Subnet", "1.2.3.4")

    for script in Script:
        foo.add_script(script)

    foo.cmd("start")
    foo[Script.TINC_UP].wait()
    foo[Script.SUBNET_UP].wait()

    if os.name != "nt":
        foo.cmd("set", "ScriptsInterpreter", path.PYTHON_PATH)

    foo.cmd("stop")
    foo[Script.SUBNET_DOWN].wait()
    foo[Script.TINC_DOWN].wait()


def test_high_scripts(ctx: Test) -> None:
    """Test that only tinc-up/subnet-up work on highest isolation level."""
    foo = init(ctx, "high")
    foo.cmd("set", "Subnet", "1.2.3.4")

    for script in Script:
        foo.add_script(script)

    foo.cmd("start")
    for script in Script.TINC_UP, Script.SUBNET_UP:
        foo[script].wait()

    time.sleep(1)
    foo.cmd("stop")

    while True:
        try:
            foo.cmd("pid", code=1)
            break
        except ValueError:
            time.sleep(0.5)

    log.info("check that no other scripts were called")
    for script in Script.SUBNET_DOWN, Script.TINC_DOWN:
        check.false(foo[script].wait(0.01))


def create_exec_proxy() -> str:
    """Create a fake exec proxy that stops the test with an error."""
    code = f"""
import os
import signal

os.kill({os.getpid()}, signal.SIGTERM)
"""
    return util.temp_file(code)


def test_exec_proxy_does_not_start_on_high(ctx: Test) -> None:
    """Check that tincd does not start if both exec proxy and high level are set."""
    foo = init(ctx, "high")
    foo.cmd("set", "Proxy", "exec", path.PYTHON_INTERPRETER)
    foo.cmd("start", code=1)


def test_bad_sandbox_level(ctx: Test, level: str) -> None:
    """Check that tincd does not start if a bad sandbox level is used."""
    foo = init(ctx, level)
    foo.cmd("start", code=1)


def test_exec_proxy_high(ctx: Test) -> None:
    """Test that exec proxy does not work at maximum isolation."""
    foo, bar = init(ctx, "high"), init(ctx, "high")

    foo.add_script(Script.TINC_UP)
    foo.start()

    proxy = create_exec_proxy()
    foo.cmd("set", "Proxy", "exec", f"{path.PYTHON_INTERPRETER} {proxy}")

    cmd.exchange(foo, bar)
    bar.cmd("set", f"{foo}.Port", str(foo.port))

    bar.add_script(Script.TINC_UP)
    bar.cmd("start")
    bar[Script.TINC_UP].wait()

    time.sleep(1)

    bar.cmd("stop")
    foo.cmd("stop")


with Test("all scripts work at level 'off'") as context:
    test_scripts_work(context, "off")

if HAVE_SANDBOX:
    with Test("all scripts work at level 'normal'") as context:
        test_scripts_work(context, "normal")

    with Test("only tinc-up and first subnet-up work at level 'high'") as context:
        test_high_scripts(context)

    with Test("tincd does not start with exec proxy and level 'high'") as context:
        test_exec_proxy_does_not_start_on_high(context)

    with Test("tincd does not start with bad sandbox level") as context:
        test_bad_sandbox_level(context, "foobar")

    with Test("exec proxy does not work at level 'high'") as context:
        test_exec_proxy_high(context)
else:
    with Test("tincd does not start with bad sandbox level") as context:
        for lvl in "normal", "high", "foobar":
            test_bad_sandbox_level(context, lvl)
