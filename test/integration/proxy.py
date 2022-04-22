#!/usr/bin/env python3

"""Test that tincd works through proxies."""

import os
import re
import time
import typing as T
import multiprocessing.connection as mp
import logging
import select
import socket
import struct

from threading import Thread
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from testlib import check, cmd, path, util
from testlib.proc import Tinc, Script
from testlib.test import Test
from testlib.util import random_string
from testlib.log import log
from testlib.feature import HAVE_SANDBOX

USERNAME = random_string(8)
PASSWORD = random_string(8)

proxy_stats = {"tx": 0}

# socks4
SOCKS_VERSION_4 = 4
CMD_STREAM = 1
REQUEST_GRANTED = 0x5A

# socks5
SOCKS_VERSION_5 = 5
METHOD_NONE = 0
METHOD_USERNAME_PASSWORD = 2
NO_METHODS = 0xFF
ADDR_TYPE_IPV4 = 1
ADDR_TYPE_DOMAIN = 3
CMD_CONNECT = 1
REP_SUCCESS = 0
RESERVED = 0
AUTH_OK = 0
AUTH_FAILURE = 0xFF


def send_all(sock: socket.socket, data: bytes) -> bool:
    """Send all data to socket, retrying as necessary."""

    total = 0

    while total < len(data):
        sent = sock.send(data[total:])
        if sent <= 0:
            break
        total += sent

    return total == len(data)


def proxy_data(client: socket.socket, remote: socket.socket) -> None:
    """Pipe data between the two sockets."""

    while True:
        read, _, _ = select.select([client, remote], [], [])

        if client in read:
            data = client.recv(4096)
            proxy_stats["tx"] += len(data)
            log.debug("received from client: '%s'", data)
            if not data or not send_all(remote, data):
                log.info("remote finished")
                return

        if remote in read:
            data = remote.recv(4096)
            proxy_stats["tx"] += len(data)
            log.debug("sending to client: '%s'", data)
            if not data or not send_all(client, data):
                log.info("client finished")
                return


def error_response(address_type: int, error: int) -> bytes:
    """Create error response for SOCKS client."""
    return struct.pack("!BBBBIH", SOCKS_VERSION_5, error, 0, address_type, 0, 0)


def read_ipv4(sock: socket.socket) -> str:
    """Read IPv4 address from socket and convert it into a string."""
    ip_addr = sock.recv(4)
    return socket.inet_ntoa(ip_addr)


def ip_to_int(addr: str) -> int:
    """Convert address to integer."""
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def addr_response(address, port: T.Tuple[str, int]) -> bytes:
    """Create address response. Format:
    version    rep    rsv    atyp    bind_addr    bind_port
    """
    return struct.pack(
        "!BBBBIH",
        SOCKS_VERSION_5,
        REP_SUCCESS,
        RESERVED,
        ADDR_TYPE_IPV4,
        ip_to_int(address),
        port,
    )


class ProxyServer(StreamRequestHandler):
    """Parent class for proxy server implementations."""

    name: T.ClassVar[str] = ""


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    """TCPServer which handles each request in a separate thread."""


class HttpProxy(ProxyServer):
    """HTTP proxy server that handles CONNECT requests."""

    name = "http"
    _re = re.compile(r"CONNECT ([^:]+):(\d+) HTTP/1\.[01]")

    def handle(self) -> None:
        try:
            self._handle_connection()
        finally:
            self.server.close_request(self.request)

    def _handle_connection(self) -> None:
        """Handle a single proxy connection"""
        data = b""
        while not data.endswith(b"\r\n\r\n"):
            data += self.connection.recv(1)
        log.info("got request: '%s'", data)

        match = self._re.match(data.decode("utf-8"))
        assert match

        address, port = match.groups()
        log.info("matched target address %s:%s", address, port)

        with socket.socket() as sock:
            sock.connect((address, int(port)))
            log.info("connected to target")

            self.connection.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            log.info("sent successful response")

            proxy_data(self.connection, sock)


class Socks4Proxy(ProxyServer):
    """SOCKS 4 proxy server."""

    name = "socks4"
    username = USERNAME

    def handle(self) -> None:
        try:
            self._handle_connection()
        finally:
            self.server.close_request(self.request)

    def _handle_connection(self) -> None:
        """Handle a single proxy connection."""

        version, command, port = struct.unpack("!BBH", self.connection.recv(4))
        check.equals(SOCKS_VERSION_4, version)
        check.equals(command, CMD_STREAM)
        check.port(port)

        addr = read_ipv4(self.connection)
        log.info("received address %s:%d", addr, port)

        user = ""
        while True:
            byte = self.connection.recv(1)
            if byte == b"\0":
                break
            user += byte.decode("utf-8")

        log.info("received username %s", user)
        self._check_username(user)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote:
            remote.connect((addr, port))
            logging.info("connected to %s:%s", addr, port)
            self._process_remote(remote)

    def _check_username(self, user: str) -> bool:
        """Authenticate by comparing socks4 username."""
        return user == self.username

    def _process_remote(self, sock: socket.socket) -> None:
        """Process a single proxy connection."""

        addr, port = sock.getsockname()
        reply = struct.pack("!BBHI", 0, REQUEST_GRANTED, port, ip_to_int(addr))
        log.info("sending reply %s", reply)
        self.connection.sendall(reply)

        proxy_data(self.connection, sock)


class AnonymousSocks4Proxy(Socks4Proxy):
    """socks4 server without any authentication."""

    def _check_username(self, user: str) -> bool:
        return True


class Socks5Proxy(ProxyServer):
    """SOCKS 5 proxy server."""

    name = "socks5"

    def handle(self) -> None:
        """Handle a proxy connection."""
        try:
            self._process_connection()
        finally:
            self.server.close_request(self.request)

    def _process_connection(self) -> None:
        """Handle a proxy connection."""

        methods = self._read_header()
        if not self._authenticate(methods):
            raise RuntimeError("authentication failed")

        command, address_type = self._read_command()
        address = self._read_address(address_type)
        port = struct.unpack("!H", self.connection.recv(2))[0]
        log.info("got address %s:%d", address, port)

        if command != CMD_CONNECT:
            raise RuntimeError(f"bad command {command}")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote:
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info("connected to %s:%d", address, port)

                reply = addr_response(*bind_address)
                log.debug("sending address '%s'", reply)
                self.connection.sendall(reply)

                proxy_data(self.connection, remote)
        except OSError as ex:
            log.error("socks server failed", exc_info=ex)
            reply = error_response(address_type, 5)
            self.connection.sendall(reply)
            raise ex

    def _read_address(self, address_type: int) -> str:
        """Read target address."""

        if address_type == ADDR_TYPE_IPV4:
            return read_ipv4(self.connection)

        if address_type == ADDR_TYPE_DOMAIN:
            domain_len = self.connection.recv(1)[0]
            domain = self.connection.recv(domain_len)
            return socket.gethostbyname(domain.decode())

        raise RuntimeError(f"unknown address type {address_type}")

    def _read_command(self) -> T.Tuple[int, int]:
        """Check protocol version and get command code and address type."""

        version, command, _, address_type = struct.unpack(
            "!BBBB", self.connection.recv(4)
        )
        check.equals(SOCKS_VERSION_5, version)
        return command, address_type

    @property
    def _method(self) -> int:
        """Supported authentication method."""
        return METHOD_USERNAME_PASSWORD

    def _authenticate(self, methods: T.List[int]) -> bool:
        """Perform client authentication."""

        found = self._method in methods
        choice = self._method if found else NO_METHODS
        result = struct.pack("!BB", SOCKS_VERSION_5, choice)

        log.debug("sending authentication result '%s'", result)
        self.connection.sendall(result)

        if not found:
            log.error("auth method not found in %s", methods)
            return False

        if not self._read_creds():
            log.error("could not verify credentials")
            return False

        return True

    def _read_header(self) -> T.List[int]:
        """Get the list of methods supported by the client."""

        version, methods = struct.unpack("!BB", self.connection.recv(2))
        check.equals(SOCKS_VERSION_5, version)
        check.greater(methods, 0)
        return [ord(self.connection.recv(1)) for _ in range(methods)]

    def _read_creds(self) -> bool:
        """Read and verify auth credentials."""

        version = ord(self.connection.recv(1))
        check.equals(1, version)

        user_len = ord(self.connection.recv(1))
        user = self.connection.recv(user_len).decode("utf-8")

        passw_len = ord(self.connection.recv(1))
        passw = self.connection.recv(passw_len).decode("utf-8")

        log.info("got credentials '%s', '%s'", user, passw)
        log.info("want credentials '%s', '%s'", USERNAME, PASSWORD)

        passed = user == USERNAME and passw == PASSWORD
        response = struct.pack("!BB", version, AUTH_OK if passed else AUTH_FAILURE)
        self.connection.sendall(response)

        return passed


class AnonymousSocks5Proxy(Socks5Proxy):
    """SOCKS 5 server without authentication support."""

    @property
    def _method(self) -> int:
        return METHOD_NONE

    def _read_creds(self) -> bool:
        return True


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Create a new tinc node."""

    foo, bar = ctx.node(), ctx.node()
    stdin = f"""
        init {foo}
        set Address 127.0.0.1
        set Port 0
        set DeviceType dummy
    """
    foo.cmd(stdin=stdin)

    stdin = f"""
        init {bar}
        set Address 127.0.0.1
        set Port 0
        set DeviceType dummy
    """
    bar.cmd(stdin=stdin)

    return foo, bar


def create_exec_proxy(port: int) -> str:
    """Create a fake exec proxy program."""

    code = f"""
import os
import multiprocessing.connection as mp

with mp.Client(("127.0.0.1", {port}), family="AF_INET") as client:
    client.send({{ **os.environ }})
"""
    return util.temp_file(code)


def test_proxy(ctx: Test, handler: T.Type[ProxyServer], user="", passw="") -> None:
    """Test socks proxy support."""

    foo, bar = init(ctx)

    if HAVE_SANDBOX:
        for node in foo, bar:
            node.cmd("set", "Sandbox", "high")

    bar.add_script(Script.TINC_UP)
    bar.start()

    cmd.exchange(foo, bar)
    foo.cmd("set", f"{bar}.Port", str(bar.port))

    with ThreadingTCPServer(("127.0.0.1", 0), handler) as server:
        _, port = server.server_address

        worker = Thread(target=server.serve_forever)
        worker.start()

        foo.cmd("set", "Proxy", handler.name, f"127.0.0.1 {port} {user} {passw}")

        foo.add_script(Script.TINC_UP)
        foo.cmd("start")
        foo[Script.TINC_UP].wait()
        time.sleep(1)

        foo.cmd("stop")
        bar.cmd("stop")

        server.shutdown()
        worker.join()


def test_proxy_exec(ctx: Test) -> None:
    """Test that exec proxies work as expected."""
    foo, bar = init(ctx)

    log.info("exec proxy without arguments fails")
    foo.cmd("set", "Proxy", "exec")
    _, stderr = foo.cmd("start", code=1)
    check.is_in("Argument expected for proxy type", stderr)

    log.info("exec proxy with correct arguments works")
    bar.cmd("start")
    cmd.exchange(foo, bar)

    with mp.Listener(("127.0.0.1", 0), family="AF_INET") as listener:
        port = int(listener.address[1])
        proxy = create_exec_proxy(port)

        foo.cmd("set", "Proxy", "exec", f"{path.PYTHON_INTERPRETER} {proxy}")
        foo.cmd("start")

        with listener.accept() as conn:
            env: T.Dict[str, str] = conn.recv()

            for var in "NAME", "REMOTEADDRESS", "REMOTEPORT":
                check.true(env.get(var))

            for var in "NODE", "NETNAME":
                if var in env:
                    check.true(env[var])

        os.remove(proxy)


if os.name != "nt":
    with Test("exec proxy") as context:
        test_proxy_exec(context)

with Test("HTTP CONNECT proxy") as context:
    proxy_stats["tx"] = 0
    test_proxy(context, HttpProxy)
    check.greater(proxy_stats["tx"], 0)

with Test("socks4 proxy with username") as context:
    proxy_stats["tx"] = 0
    test_proxy(context, Socks4Proxy, USERNAME)
    check.greater(proxy_stats["tx"], 0)

with Test("anonymous socks4 proxy") as context:
    proxy_stats["tx"] = 0
    test_proxy(context, AnonymousSocks4Proxy)
    check.greater(proxy_stats["tx"], 0)

with Test("authenticated socks5 proxy") as context:
    proxy_stats["tx"] = 0
    test_proxy(context, Socks5Proxy, USERNAME, PASSWORD)
    check.greater(proxy_stats["tx"], 0)

with Test("anonymous socks5 proxy") as context:
    proxy_stats["tx"] = 0
    test_proxy(context, AnonymousSocks5Proxy)
    check.greater(proxy_stats["tx"], 0)
