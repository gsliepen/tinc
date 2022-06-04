"""Wrappers for more complicated tinc/tincd commands."""

import typing as T

from . import check
from .log import log
from .proc import Tinc

ExchangeIO = T.Tuple[
    T.Tuple[str, str],
    T.Tuple[str, str],
    T.Tuple[str, str],
]


def connect(node0: Tinc, node1: Tinc) -> ExchangeIO:
    """Exchange configuration between nodes and start
    them in such an order that `Port 0` works on both sides.
    """
    node0.add_script(node1.script_up)
    node0.start()
    result = exchange(node0, node1)
    node1.add_script(node0.script_up)
    node1.cmd("add", "ConnectTo", node0.name)
    node1.start()
    node0[node1.script_up].wait()
    node1[node0.script_up].wait()
    return result


def exchange(node0: Tinc, node1: Tinc, export_all: bool = False) -> ExchangeIO:
    """Run `export(-all) | exchange | import` between the passed nodes.
    `export-all` is used if export_all is set to True.
    """
    export_cmd = "export-all" if export_all else "export"
    log.debug("%s between %s and %s", export_cmd, node0.name, node1.name)

    exp_out, exp_err = node0.cmd(export_cmd)
    log.debug(
        'exchange: %s %s returned ("%s", "%s")', export_cmd, node0, exp_out, exp_err
    )
    check.is_in("Name =", exp_out)

    xch_out, xch_err = node1.cmd("exchange", stdin=exp_out)
    log.debug('exchange: exchange %s returned ("%s", "%s")', node1, xch_out, xch_err)
    check.is_in("Name =", xch_out)
    check.is_in("Imported ", xch_err)

    imp_out, imp_err = node0.cmd("import", stdin=xch_out)
    log.debug('exchange: import %s returned ("%s", "%s")', node0, imp_out, imp_err)
    check.is_in("Imported ", imp_err)

    return (
        (exp_out, exp_err),
        (xch_out, xch_err),
        (imp_out, imp_err),
    )


def get(tinc: Tinc, var: str) -> str:
    """Get the value of the variable, stripped of whitespace."""
    assert var
    stdout, _ = tinc.cmd("get", var)
    return stdout.strip()
