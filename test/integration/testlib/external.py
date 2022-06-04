"""Wrappers for running external commands."""

import subprocess as subp
import atexit
import typing as T

from .log import log
from .util import random_string

_netns_created: T.Set[str] = set()
_iface_created: T.Set[str] = set()


def _cleanup() -> None:
    for namespace in _netns_created.copy():
        netns_delete(namespace)

    # Ignore errors since device may have been moved to a different netns
    for iface in _iface_created.copy():
        subp.run(["ip", "link", "delete", iface], check=False)


atexit.register(_cleanup)


def _netns_action(action: str, namespace: str) -> bool:
    log.debug("%s network namespace %s", action, namespace)

    res = subp.run(["ip", "netns", action, namespace], check=False)
    if res.returncode:
        log.error("could not %s netns %s", action, namespace)
    else:
        log.debug("OK %s netns %s", action, namespace)

    return not res.returncode


def netns_delete(namespace: str) -> bool:
    """Remove a previously created network namespace."""
    success = _netns_action("delete", namespace)
    if success:
        _netns_created.remove(namespace)
    return success


def netns_add(namespace: str) -> bool:
    """Add a network namespace (which can be removed manually or automatically at exit)."""
    success = _netns_action("add", namespace)
    if success:
        _netns_created.add(namespace)
    return success


def netns_exec(netns: str, *args: str, check: bool = False) -> subp.CompletedProcess:
    """Execute command in the network namespace."""
    return subp.run(["ip", "netns", "exec", netns, *args], check=check)


def ping(address: str, netns: T.Optional[str] = None) -> bool:
    """Ping the address from inside the network namespace."""
    args = ["ping", "-l1", "-W1", "-i0.1", "-c10", address]
    if netns:
        proc = netns_exec(netns, *args)
    else:
        proc = subp.run(args, check=False)
    return proc.returncode == 0


def move_dev(netns: str, device: str, ip_addr: str) -> None:
    """Move device to the network namespace."""
    if netns not in _netns_created:
        netns_add(netns)
    subp.run(["ip", "link", "set", device, "netns", netns], check=True)
    netns_exec(netns, "ip", "addr", "add", ip_addr, "dev", device, check=True)
    netns_exec(netns, "ip", "link", "set", device, "up", check=True)


def veth_add(name0: str, name1: str) -> None:
    """Create a veth link pair."""
    subp.run(
        ["ip", "link", "add", name0, "type", "veth", "peer", "name", name1], check=True
    )
    _iface_created.add(name0)


def link_add(link_type: str) -> str:
    """Create a virtual link."""
    name = random_string(10)
    if link_type in ("tun", "tap"):
        subp.run(["ip", "tuntap", "add", "mode", link_type, "dev", name], check=True)
    else:
        subp.run(["ip", "link", "add", name, "type", link_type], check=True)
    _iface_created.add(name)
    return name
