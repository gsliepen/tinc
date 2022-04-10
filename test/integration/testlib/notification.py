"""Support for receiving notifications from tincd scripts."""

import os
import signal
import threading
import queue
import multiprocessing.connection as mp
import typing as T

from .log import log
from .event import Notification
from .const import MPC_FAMILY


def _get_key(name, script) -> str:
    return f"{name}/{script}"


class NotificationServer:
    """Receive event notifications from tincd scripts."""

    address: T.Union[str, bytes]
    authkey: bytes  # only to prevent accidental connections to wrong servers
    _lock: threading.Lock
    _ready: threading.Event
    _worker: T.Optional[threading.Thread]
    _notifications: T.Dict[str, queue.Queue]

    def __init__(self) -> None:
        self.address = ""
        self.authkey = os.urandom(8)
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._worker = threading.Thread(target=self._recv, daemon=True)
        self._notifications = {}

        log.debug("using authkey %s", self.authkey)

        self._worker.start()
        log.debug("waiting for notification worker to become ready")

        self._ready.wait()
        log.debug("notification worker is ready")

    @T.overload
    def get(self, node: str, script: str) -> Notification:
        """Receive notification from the specified node and script without a timeout.
        Doesn't return until a notification arrives.
        """
        return self.get(node, script)

    @T.overload
    def get(self, node: str, script: str, timeout: float) -> T.Optional[Notification]:
        """Receive notification from the specified node and script with a timeout.
        If nothing arrives before it expires, None is returned.
        """
        return self.get(node, script, timeout)

    def get(
        self, node: str, script: str, timeout: T.Optional[float] = None
    ) -> T.Optional[Notification]:
        """Receive notification from specified node and script. See overloads above."""

        key = _get_key(node, script)
        with self._lock:
            que = self._notifications.get(key, queue.Queue())
            self._notifications[key] = que
        try:
            return que.get(timeout=timeout)
        except queue.Empty:
            return None

    def _recv(self) -> None:
        try:
            self._listen()
        except (OSError, AssertionError) as ex:
            log.error("recv notifications failed", exc_info=ex)
            os.kill(0, signal.SIGTERM)

    def _listen(self) -> None:
        with mp.Listener(family=MPC_FAMILY, authkey=self.authkey) as listener:
            assert not isinstance(listener.address, tuple)
            self.address = listener.address
            self._ready.set()
            while True:
                with listener.accept() as conn:
                    self._handle_conn(conn)

    def _handle_conn(self, conn: mp.Connection) -> None:
        log.debug("accepted connection")

        data: Notification = conn.recv()
        assert isinstance(data, Notification)
        data.update_time()

        key = _get_key(data.node, data.script)
        log.debug('from "%s" received data "%s"', key, data)

        with self._lock:
            que = self._notifications.get(key, queue.Queue())
            self._notifications[key] = que
        que.put(data)


notifications = NotificationServer()
