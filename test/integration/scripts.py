#!/usr/bin/env python3

"""Test that all tincd scripts execute in correct order and contain expected env vars."""

import os
import typing as T

from testlib import check, path
from testlib.log import log
from testlib.proc import Tinc, Script, ScriptType, TincScript
from testlib.test import Test
from testlib.util import random_string

SUBNET_SERVER = ("10.0.0.1", "fec0::/64")
SUBNET_CLIENT = ("10.0.0.2", "fec0::/64#5")
NETNAMES = {
    "server": "net_" + random_string(8),
    "invite": "net_" + random_string(8),
    "client": "net_" + random_string(8),
}

# Creation time for the last notification event we've received.
# Used for checking that scripts are called in the correct order.
# dict is to avoid angering linters by using `global` to update this value.
last_time = {"time": -1}


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    server, client = ctx.node(), ctx.node()

    stdin = f"""
        init {server}
        set Port 0
        set DeviceType dummy
        set Address 127.0.0.1
        set AddressFamily ipv4
        add Subnet {SUBNET_SERVER[0]}
        add Subnet {SUBNET_SERVER[1]}
    """
    server.cmd(stdin=stdin)

    for script in (
        *Script,
        server.script_up,
        server.script_down,
        client.script_up,
        client.script_down,
    ):
        server.add_script(script)

    return server, client


def wait_script(script: TincScript) -> T.Dict[str, str]:
    """Wait for script to finish and check that it was run by tincd *after* the
    script that was used as the argument in the previous call to this function.

    For example, to check that SUBNET_UP is called after TINC_UP:
        wait_script(node[Script.TINC_UP])
        wait_script(node[Script.SUBNET_UP])
    """
    msg = script.wait()
    assert msg.created_at

    log.debug(
        "%s sent %d, prev %d, diff %d",
        script,
        msg.created_at,
        last_time["time"],
        msg.created_at - last_time["time"],
    )

    if msg.created_at <= last_time["time"]:
        raise ValueError(f"script {script} started in wrong order")

    last_time["time"] = msg.created_at
    return msg.env


def wait_tinc(server: Tinc, script: Script) -> None:
    """Wait for TINC_UP / TINC_DOWN and check env vars."""
    log.info("checking tinc: %s %s", server, script)

    env = wait_script(server[script])
    check.equals(NETNAMES["server"], env["NETNAME"])
    check.equals(server.name, env["NAME"])
    check.equals("dummy", env["DEVICE"])


def wait_subnet(server: Tinc, script: Script, node: Tinc, subnet: str) -> None:
    """Wait for SUBNET_UP / SUBNET_DOWN and check env vars."""
    log.info("checking subnet: %s %s %s %s", server, script, node, subnet)

    env = wait_script(server[script])
    check.equals(NETNAMES["server"], env["NETNAME"])
    check.equals(server.name, env["NAME"])
    check.equals("dummy", env["DEVICE"])
    check.equals(node.name, env["NODE"])

    if node != server:
        check.equals("127.0.0.1", env["REMOTEADDRESS"])
        check.equals(str(node.port), env["REMOTEPORT"])

    if "#" in subnet:
        addr, weight = subnet.split("#")
        check.equals(addr, env["SUBNET"])
        check.equals(weight, env["WEIGHT"])
    else:
        check.equals(subnet, env["SUBNET"])


def wait_host(server: Tinc, client: Tinc, script: ScriptType) -> None:
    """Wait for HOST_UP / HOST_DOWN and check env vars."""
    log.info("checking host: %s %s %s", server, client, script)

    env = wait_script(server[script])
    check.equals(NETNAMES["server"], env["NETNAME"])
    check.equals(server.name, env["NAME"])
    check.equals(client.name, env["NODE"])
    check.equals("dummy", env["DEVICE"])
    check.equals("127.0.0.1", env["REMOTEADDRESS"])
    check.equals(str(client.port), env["REMOTEPORT"])


def test_start_server(server: Tinc) -> None:
    """Start server node and run checks on its scripts."""
    server.cmd("-n", NETNAMES["server"], "start")
    wait_tinc(server, Script.TINC_UP)

    port = server.read_port()
    server.cmd("set", "port", str(port))

    log.info("test server subnet-up")
    for sub in SUBNET_SERVER:
        wait_subnet(server, Script.SUBNET_UP, server, sub)


def test_invite_client(server: Tinc, client: Tinc) -> str:
    """Check that client invitation scripts work."""
    url, _ = server.cmd("-n", NETNAMES["invite"], "invite", client.name)
    url = url.strip()
    check.true(url)

    env = wait_script(server[Script.INVITATION_CREATED])
    check.equals(NETNAMES["invite"], env["NETNAME"])
    check.equals(server.name, env["NAME"])
    check.equals(client.name, env["NODE"])
    check.equals(url, env["INVITATION_URL"])
    assert os.path.isfile(env["INVITATION_FILE"])

    return url


def test_join_client(server: Tinc, client: Tinc, url: str) -> None:
    """Test that client joining scripts work."""
    client.cmd("-n", NETNAMES["client"], "join", url)

    env = wait_script(server[Script.INVITATION_ACCEPTED])
    check.equals(NETNAMES["server"], env["NETNAME"])
    check.equals(server.name, env["NAME"])
    check.equals(client.name, env["NODE"])
    check.equals("dummy", env["DEVICE"])
    check.equals("127.0.0.1", env["REMOTEADDRESS"])


def test_start_client(server: Tinc, client: Tinc) -> None:
    """Start client and check its script work."""
    client.randomize_port()

    stdin = f"""
        set Address {client.address}
        set ListenAddress {client.address}
        set Port {client.port}
        set DeviceType dummy
        add Subnet {SUBNET_CLIENT[0]}
        add Subnet {SUBNET_CLIENT[1]}
        start
    """
    client.cmd(stdin=stdin)

    log.info("test client scripts")
    wait_host(server, client, Script.HOST_UP)
    wait_host(server, client, client.script_up)

    log.info("test client subnet-up")
    for sub in SUBNET_CLIENT:
        wait_subnet(server, Script.SUBNET_UP, client, sub)


def test_stop_server(server: Tinc, client: Tinc) -> None:
    """Stop server and check that its scripts work."""
    server.cmd("stop")
    wait_host(server, client, Script.HOST_DOWN)
    wait_host(server, client, client.script_down)

    log.info("test client subnet-down")
    for sub in SUBNET_CLIENT:
        wait_subnet(server, Script.SUBNET_DOWN, client, sub)

    log.info("test server subnet-down")
    for sub in SUBNET_SERVER:
        wait_subnet(server, Script.SUBNET_DOWN, server, sub)

    log.info("test tinc-down")
    wait_tinc(server, Script.TINC_DOWN)


def run_tests(ctx: Test) -> None:
    """Run all tests."""
    server, client = init(ctx)

    log.info("start server")
    test_start_server(server)

    log.info("invite client")
    url = test_invite_client(server, client)

    log.info('join client via url "%s"', url)
    test_join_client(server, client, url)

    log.info("start client")
    test_start_client(server, client)

    log.info("stop server")
    test_stop_server(server, client)


def run_script_interpreter_test(ctx: Test) -> None:
    """Check that tincd scripts run with a custom script interpreter."""
    foo = ctx.node()
    stdin = f"""
        init {foo}
        set Port 0
        set DeviceType dummy
        set ScriptsInterpreter {path.PYTHON_PATH}
    """
    foo_up = foo.add_script(Script.TINC_UP)
    foo.cmd(stdin=stdin)

    foo.cmd("start")
    foo_up.wait()
    foo.cmd("stop")


with Test("scripts test") as context:
    run_tests(context)

if os.name != "nt":
    with Test("works with ScriptInterpreter") as context:
        run_script_interpreter_test(context)
