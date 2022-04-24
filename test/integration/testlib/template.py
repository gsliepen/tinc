"""Various script and configuration file templates."""

import os
import typing as T
from string import Template

from . import path
from .notification import notifications


_CMD_VARS = os.linesep.join([f"set {var}={val}" for var, val in path.env.items()])


def _read_template(tpl_name: str, maps: T.Dict[str, T.Any]) -> str:
    tpl_path = path.TESTLIB_ROOT.joinpath("template", tpl_name)
    tpl = Template(tpl_path.read_text(encoding="utf-8"))
    return tpl.substitute(maps)


def make_script(node: str, script: str, source: str) -> str:
    """Create a tincd script."""
    addr = notifications.address
    if isinstance(addr, str):
        addr = f'r"{addr}"'  # 'r' is for Windows pipes: \\.\foo\bar
    maps = {
        "AUTH_KEY": notifications.authkey,
        "CWD": path.CWD,
        "NODE_NAME": node,
        "NOTIFICATIONS_ADDR": addr,
        "PYTHON_PATH": path.PYTHON_PATH,
        "SCRIPT_NAME": script,
        "SCRIPT_SOURCE": source,
        "SRC_ROOT": path.TEST_SRC_ROOT,
        "TEST_NAME": path.TEST_NAME,
    }
    return _read_template("script.py.tpl", maps)


def make_cmd_wrap(script: str) -> str:
    """Create a .cmd wrapper for tincd script. Only makes sense on Windows."""
    maps = {
        "PYTHON_CMD": path.PYTHON_CMD,
        "PYTHON_PATH": path.PYTHON_PATH,
        "SCRIPT_PATH": script,
        "VARIABLES": _CMD_VARS,
    }
    return _read_template("script.cmd.tpl", maps)


def make_netns_config(namespace: str, ip_addr: str, mask: int) -> str:
    """Create a tincd script that does network namespace configuration."""
    maps = {"NAMESPACE": namespace, "ADDRESS": ip_addr, "MASK": mask}
    return _read_template("netns.py.tpl", maps)
