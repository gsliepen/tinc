#!/usr/bin/env python3

"""Test inviting tinc nodes through tinc-up script."""

import os
import typing as T

from testlib import check, util
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test

IFCONFIG = "93.184.216.34/24"
ROUTES_IPV6 = ("2606:2800:220:1::/64", "2606:2800:220:1:248:1893:25c8:1946")
BAD_IPV4 = "1234::"
ED_PUBKEY = "Ed25519PublicKey"


def make_inv_created(export_output: str) -> str:
    """Generate script for invitation-created script."""
    return f'''
    node, invite = os.environ['NODE'], os.environ['INVITATION_FILE']
    log.info('writing to invitation file %s, node %s', invite, node)

    script = f"""
Name = {{node}}
Ifconfig = {IFCONFIG}
Route = {' '.join(ROUTES_IPV6)}
Route = 1.2.3.4 {BAD_IPV4}

{export_output}
""".strip()

    with open(invite, 'w', encoding='utf-8') as f:
        f.write(script)
    '''


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar = ctx.node(init=True), ctx.node()
    foo.start()
    return foo, bar


def run_tests(ctx: Test) -> None:
    """Run all tests."""
    foo, bar = init(ctx)

    log.info("run export")
    export, _ = foo.cmd("export")
    assert export

    log.info("adding invitation-created script")
    code = make_inv_created(export)
    foo.add_script(Script.INVITATION_CREATED, code)

    log.info("inviting %s", bar)
    url, _ = foo.cmd("invite", bar.name)
    url = url.strip()
    assert url

    log.info('joining %s to %s with "%s"', bar, foo, url)
    bar.cmd("--batch", "join", url)
    bar.cmd("set", "Port", "0")

    log.info("comparing host configs")
    check.files_eq(foo.sub("hosts", foo.name), bar.sub("hosts", foo.name))

    log.info("comparing public keys")
    foo_key = util.find_line(foo.sub("hosts", bar.name), ED_PUBKEY)
    bar_key = util.find_line(bar.sub("hosts", bar.name), ED_PUBKEY)
    check.equals(foo_key, bar_key)

    log.info("bar.tinc-up must not exist")
    assert not os.path.exists(bar.sub("tinc-up"))

    inv = bar.sub("tinc-up.invitation")
    log.info("testing %s", inv)

    content = util.read_text(inv)
    check.is_in(IFCONFIG, content)
    check.not_in(BAD_IPV4, content)

    for route in ROUTES_IPV6:
        check.is_in(route, content)

    if os.name != "nt":
        assert not os.access(inv, os.X_OK)


with Test("invite-tinc-up") as context:
    run_tests(context)
