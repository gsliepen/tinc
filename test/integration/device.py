#!/usr/bin/env python3

"""Test device configuration variables."""

import os
import platform
import typing as T

from testlib import check
from testlib.feature import Feature
from testlib.log import log
from testlib.proc import Script
from testlib.test import Test

system = platform.system()


def unknown_device_types(
    features: T.Container[Feature],
) -> T.Generator[str, T.Any, None]:
    """Get devices unsupported by current OS."""

    yield "foobar"

    if Feature.UML not in features:
        yield "uml"

    if Feature.TUNEMU not in features:
        yield "tunemu"

    if system != "Darwin":
        if not system.endswith("BSD"):
            yield "tunnohead"
            yield "tunifhead"

        yield "utun"

    if system == "Windows":
        yield "tun"
        yield "tap"


def test_unknown_types(ctx: Test) -> None:
    """Test unknown device types."""

    foo = ctx.node(init=True)

    for dev_type in unknown_device_types(foo.features):
        log.info("testing unknown device type %s", dev_type)
        _, err = foo.cmd("start", "-o", f"DeviceType={dev_type}", code=1)
        check.is_in(f"Unknown device type {dev_type}", err)


def test_device_standby(ctx: Test) -> None:
    """Test DeviceStandby."""

    foo, bar, baz = ctx.node(init=True), ctx.node(), ctx.node()

    log.info("configure %s", foo)
    foo.cmd("set", "DeviceStandby", "yes")
    foo.add_script(Script.TINC_UP)
    foo.add_script(Script.TINC_DOWN)

    log.info("starting tincd must not call tinc-up")
    foo.cmd("start")
    assert not foo[Script.TINC_UP].wait(timeout=1)

    log.info("invite %s", bar)
    url, _ = foo.cmd("invite", bar.name)
    bar.cmd("join", url.strip())
    bar.cmd("set", "DeviceType", "dummy")
    bar.cmd("set", "Port", "0")

    log.info("invite %s", baz)
    url, _ = foo.cmd("invite", baz.name)
    baz.cmd("join", url.strip())
    baz.cmd("set", "DeviceType", "dummy")
    baz.cmd("set", "Port", "0")

    log.info("starting first client must call tinc-up")
    bar.start()
    foo[Script.TINC_UP].wait()

    log.info("starting second client must not call tinc-up")
    baz.start()
    assert not foo[Script.TINC_UP].wait(timeout=1)

    log.info("stopping next-to-last client must not call tinc-down")
    bar.add_script(Script.TINC_DOWN)
    bar.cmd("stop")
    bar[Script.TINC_DOWN].wait()
    assert not foo[Script.TINC_DOWN].wait(timeout=1)

    log.info("stopping last client must call tinc-down")
    baz.cmd("stop")
    foo[Script.TINC_DOWN].wait()

    log.info("stopping tincd must not call tinc-down")
    foo.cmd("stop")
    assert not foo[Script.TINC_DOWN].wait(timeout=1)


# Device types are not checked on Windows.
# /dev/net/tun is not available in Docker containers.
if system != "Windows" and (system != "Linux" or os.path.exists("/dev/net/tun")):
    with Test("unknown device types") as context:
        test_unknown_types(context)

if system != "Windows":
    with Test("test DeviceStandby = yes") as context:
        test_device_standby(context)
