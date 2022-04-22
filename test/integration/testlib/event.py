"""Classes for doing data exchange between test and tincd scripts."""

import os
import sys
import time
import platform
import typing as T

_MONOTONIC_IS_SYSTEMWIDE = not (
    platform.system() == "Darwin" and sys.version_info < (3, 10)
)


def _time_ns() -> int:
    if sys.version_info <= (3, 7):
        return int(time.monotonic() * 1e9)
    return time.monotonic_ns()


class Notification:
    """Notification about tinc script execution."""

    test: str
    node: str
    script: str
    created_at: T.Optional[int] = None
    env: T.Dict[str, str]
    args: T.Dict[str, str]
    error: T.Optional[Exception]

    def __init__(self) -> None:
        self.env = dict(os.environ)

        # This field is used to record when the notification was created. On most
        # operating systems, it uses system-wide monotonic time which is the same
        # for all processes. Not on macOS, at least not before Python 3.10. So if
        # we're running such a setup, assign time local to our test process right
        # when we receive the notification to have a common reference point to
        # all measurements.
        if _MONOTONIC_IS_SYSTEMWIDE:
            self.update_time()

    def __str__(self) -> str:
        return f"{self.test}/{self.node}/{self.script}"

    def update_time(self) -> None:
        """Update creation time if it was not assigned previously."""
        if self.created_at is None:
            self.created_at = _time_ns()
