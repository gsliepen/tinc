"""Wrappers for running external commands."""

import subprocess as subp
import atexit
import typing as T

from .log import log

_netns_created: T.Set[str] = set()


def _netns_cleanup() -> None:
    for namespace in _netns_created.copy():
        netns_delete(namespace)


atexit.register(_netns_cleanup)


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
