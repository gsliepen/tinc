#!/usr/bin/env python3

"""Test basic SPTPS features."""

import os
import subprocess as subp
import re

from testlib import path, util, check
from testlib.log import log

port_re = re.compile(r"Listening on (\d+)\.\.\.")


class Keypair:
    """Create public/private keypair using sptps_keypair."""

    private: str
    public: str

    def __init__(self, name: str) -> None:
        self.private = os.path.join(path.TEST_WD, f"{name}.priv")
        self.public = os.path.join(path.TEST_WD, f"{name}.pub")
        subp.run([path.SPTPS_KEYPAIR_PATH, self.private, self.public], check=True)


log.info("generate keys")
server_key = Keypair("server")
client_key = Keypair("client")

log.info("transfer random data")
DATA = util.random_string(256).encode("utf-8")


def run_client(port: int, key_priv: str, key_pub: str, *flags: str) -> None:
    """Start client version of sptps_test."""
    client_cmd = [
        path.SPTPS_TEST_PATH,
        "-4",
        "-q",
        *flags,
        key_priv,
        key_pub,
        "localhost",
        str(port),
    ]
    log.info('start client with "%s"', " ".join(client_cmd))
    subp.run(client_cmd, input=DATA, check=True)


def get_port(server: subp.Popen) -> int:
    """Get port that sptps_test server is listening on."""
    assert server.stderr
    while True:
        line = server.stderr.readline().decode("utf-8")
        match = port_re.match(line)
        if match:
            return int(match[1])
        log.debug("waiting for server to start accepting connections")


def test(key0: Keypair, key1: Keypair, *flags: str) -> None:
    """Run tests using the supplied keypair."""
    server_cmd = [path.SPTPS_TEST_PATH, "-4", *flags, key0.private, key1.public, "0"]
    log.info('start server with "%s"', " ".join(server_cmd))

    with subp.Popen(server_cmd, stdout=subp.PIPE, stderr=subp.PIPE) as server:
        assert server.stdout

        port = get_port(server)
        run_client(port, key1.private, key0.public, *flags)

        received = b""
        while len(received) < len(DATA):
            received += server.stdout.read()

        if server.returncode is None:
            server.kill()

    check.equals(DATA, received)


def run_keypair_tests(*flags: str) -> None:
    """Run tests on all generated keypairs."""
    log.info("running tests with (client, server) keypair and flags %s", flags)
    test(server_key, client_key)

    log.info("running tests with (server, client) keypair and flags %s", flags)
    test(client_key, server_key)


log.info("running tests in stream mode")
run_keypair_tests()

log.info("running tests in datagram mode")
run_keypair_tests("-dq")
