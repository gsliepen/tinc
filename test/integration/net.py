#!/usr/bin/env python3

"""Test various network-related configuration variables."""

from testlib import check, cmd
from testlib.test import Test


def test_tunnel_server(ctx: Test, enabled: bool) -> None:
    """Test TunnelServer."""

    foo, mid, bar = (
        ctx.node(init=True),
        ctx.node(init=f"set TunnelServer {'yes' if enabled else 'no'}"),
        ctx.node(init=True),
    )

    mid.start()

    for peer in foo, bar:
        cmd.exchange(peer, mid)
        peer.cmd("add", "ConnectTo", mid.name)
        peer.add_script(mid.script_up)
        peer.start()

    foo[mid.script_up].wait()
    bar[mid.script_up].wait()

    edge_peers = 2 if enabled else 3

    check.nodes(foo, edge_peers)
    check.nodes(mid, 3)
    check.nodes(bar, edge_peers)


with Test("test TunnelServer = yes") as context:
    test_tunnel_server(context, True)

with Test("test TunnelServer = no") as context:
    test_tunnel_server(context, False)
