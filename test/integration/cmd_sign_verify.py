#!/usr/bin/env python3

"""Test sign/verify commands."""

import os
import tempfile

from testlib import util, cmd, check
from testlib.proc import Tinc
from testlib.test import Test

PRIV_KEY = """
-----BEGIN ED25519 PRIVATE KEY-----
4Q8bJqfN60s0tOiZdAhAWLgB9+o947cta2WMXmQIz8mCdBdcphzhp23Wt2vUzfQ6
XHt9+5IqidIw/lLXG61Nbc6IZ+4Fy1XOO1uJ6j4hqIKjdSytD2Vb7MPlNJfPdCDu
-----END ED25519 PRIVATE KEY-----
"""

HOST = """
Ed25519PublicKey = nOSmPehc9ljTtbi+IeoKiyYnkc7gd12OzTZTy3TnwgL
Port = 17879
"""

# Do not replace \n or this will break on Windows if cloned with native line endings
SIGNED_BYTES = """Signature = foo 1653397516 \
T8Bjg7dc7IjsCrZQC/20qLRsWPlrbthnjyDHQM0BMLoTeAHbLt0fxP5CbTy7Cifgg7P0K179GeahBFsnaIr4MA\n\
fake testing data\n\
hello there\n\
""".encode(
    "utf-8"
)

RAW_DATA = tempfile.mktemp()

with open(RAW_DATA, "wb") as raw_file:
    raw_file.write(util.random_string(64).encode("utf-8"))


def init(ctx: Test) -> Tinc:
    """Initialize a node."""

    foo = ctx.node()
    stdin = f"init {foo}"
    foo.cmd(stdin=stdin)
    return foo


def test_sign_errors(foo: Tinc) -> None:
    """Test `sign` error conditions."""

    _, err = foo.cmd("sign", "foo", "bar", code=1)
    check.is_in("Too many arguments", err)

    _, err = foo.cmd("sign", "/nonexistent", code=1)
    check.is_in("Could not open", err)

    os.truncate(foo.sub("ed25519_key.priv"), 0)
    _, err = foo.cmd("sign", RAW_DATA, code=1)
    check.is_in("Could not read private key from", err)

    os.remove(foo.sub("ed25519_key.priv"))
    _, err = foo.cmd("sign", RAW_DATA, code=1)
    check.is_in("Could not open", err)


def test_verify(foo: Tinc) -> None:
    """Test `verify` of data known to work."""

    signed_file = tempfile.mktemp()
    with open(signed_file, "wb") as f:
        f.write(SIGNED_BYTES)

    foo.name = "foo"
    util.write_text(foo.sub("tinc.conf"), f"Name = {foo}")
    util.write_text(foo.sub(f"hosts/{foo}"), HOST)
    util.write_text(foo.sub("ed25519_key.priv"), PRIV_KEY)

    for name in ".", foo.name:
        foo.cmd("verify", name, stdin=SIGNED_BYTES)
        foo.cmd("verify", name, signed_file)

    if os.name != "nt":
        foo.cmd("verify", "*", stdin=SIGNED_BYTES)
        foo.cmd("verify", "*", signed_file)

    os.remove(signed_file)


def test_verify_errors(foo: Tinc) -> None:
    """Test `verify` error conditions."""

    _, err = foo.cmd("verify", code=1)
    check.is_in("Not enough arguments", err)

    _, err = foo.cmd("verify", foo.name, "bar", "baz", code=1)
    check.is_in("Too many arguments", err)

    _, err = foo.cmd("verify", "foo@", code=1)
    check.is_in("Invalid node name", err)

    _, err = foo.cmd("verify", foo.name, "/nonexistent", code=1)
    check.is_in("Could not open", err)

    _, err = foo.cmd("verify", foo.name, stdin="", code=1)
    check.is_in("Invalid input", err)

    _, err = foo.cmd("verify", foo.name, stdin="Signature = foo bar baz", code=1)
    check.is_in("Invalid input", err)

    sig = (
        "Signature = dog "
        "1653395565 "
        "D25ACFD89jaV9+6g9TNMDTDxH8JGd3wLMv/YNMwXbrj9Bos9q6IW/tuFPxGxYNQ6qAc93XFzkH5u7Gw+Z86GDA\n"
    )
    _, err = foo.cmd("verify", foo.name, stdin=sig, code=1)
    check.is_in(f"Signature is not made by {foo}", err)

    sig = (
        f"Signature = {foo} "
        "1653395565 "
        "D25ACFD89jaV9+6g9TNMDTDxH8JGd3wLMv/YNMwXbrj9Bos9q6IW/tuFPxGxYNQ6qAc93XFzkH5u7Gw+Z86GDA\n"
    )
    _, err = foo.cmd("verify", foo.name, stdin=sig, code=1)
    check.is_in("Invalid signature", err)

    util.write_text(foo.sub(f"hosts/{foo}"), "foobar")
    _, err = foo.cmd("verify", foo.name, stdin=sig, code=1)
    check.is_in("Could not read public key from", err)


def test_sign_verify(foo: Tinc, bar: Tinc) -> None:
    """Test `sign` and pass its result to `verify`."""

    signed, _ = foo.cmd("sign", RAW_DATA, stdin=b"")
    assert isinstance(signed, bytes)

    signed_file = tempfile.mktemp()
    with open(signed_file, "wb") as f:
        f.write(signed)

    for name in ".", foo.name:
        foo.cmd("verify", name, signed_file)
        foo.cmd("verify", name, stdin=signed)

    if os.name != "nt":
        foo.cmd("verify", "*", signed_file)
        foo.cmd("verify", "*", stdin=signed)

    os.remove(signed_file)

    cmd.exchange(foo, bar)

    if os.name != "nt":
        signed, _ = foo.cmd("sign", RAW_DATA)
        bar.cmd("verify", "*", stdin=signed)

    signed, _ = bar.cmd("sign", RAW_DATA)
    foo.cmd("verify", bar.name, stdin=signed)


with Test("test errors in `sign`") as context:
    test_sign_errors(init(context))

with Test("test errors in `verify`") as context:
    test_verify_errors(init(context))

with Test("test successful `verify`") as context:
    test_verify(init(context))

with Test("test `sign` and `verify`") as context:
    test_sign_verify(init(context), init(context))
