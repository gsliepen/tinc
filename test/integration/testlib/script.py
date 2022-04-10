"""Classes related to creation and control of tincd scripts."""

import os
import typing as T
from enum import Enum

from .log import log
from .event import Notification
from .notification import notifications


class Script(Enum):
    """A list of supported tincd scripts.
    hosts/XXX-{up,down} are missing because we generate node names at runtime.
    """

    TINC_UP = "tinc-up"
    TINC_DOWN = "tinc-down"
    HOST_UP = "host-up"
    HOST_DOWN = "host-down"
    SUBNET_UP = "subnet-up"
    SUBNET_DOWN = "subnet-down"
    INVITATION_CREATED = "invitation-created"
    INVITATION_ACCEPTED = "invitation-accepted"


# Since we rely on dynamically created node names, we cannot put 'hosts/XXX-up' in an enum.
# This is the reason we sometimes need strings to type script variables.
ScriptType = T.Union[Script, str]


class TincScript:
    """Control created tincd scripts and receive notifications from them."""

    _node: str
    _path: str
    _script: str

    def __init__(self, node: str, script: str, path: str) -> None:
        self._node = node
        self._script = script
        self._path = path

    def __str__(self):
        return f"{self._node}/{self._script}"

    @T.overload
    def wait(self) -> Notification:
        """Wait for the script to finish, returning the notification sent by the script."""
        return self.wait()

    @T.overload
    def wait(self, timeout: float) -> T.Optional[Notification]:
        """Wait for the script to finish, returning the notification sent by the script.
        If nothing arrives before timeout expires, None is returned."""
        return self.wait(timeout)

    def wait(self, timeout: T.Optional[float] = None) -> T.Optional[Notification]:
        """Wait for the script to finish. See overloads above."""
        log.debug("waiting for script %s/%s", self._node, self._script)
        if timeout is None:
            return notifications.get(self._node, self._script)
        return notifications.get(self._node, self._script, timeout)

    @property
    def enabled(self) -> bool:
        """Check if script is enabled."""
        if os.name == "nt":
            return os.path.exists(self._path)
        return os.access(self._path, os.X_OK)

    def disable(self) -> None:
        """Disable the script by renaming it."""
        log.debug("disabling script %s/%s", self._node, self._script)
        assert self.enabled
        os.rename(self._path, self._disabled_name)

    def enable(self) -> None:
        """Enable the script by renaming it back."""
        log.debug("enabling script %s/%s", self._node, self._script)
        assert not self.enabled
        os.rename(self._disabled_name, self._path)

    @property
    def _disabled_name(self) -> str:
        return f"{self._path}.disabled"
