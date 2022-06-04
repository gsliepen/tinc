#!/usr/bin/env python3
# pylint: disable=import-outside-toplevel

"""Test key management commands."""

import os

from testlib import check, util
from testlib.log import log
from testlib.const import RUN_ACCESS_CHECKS
from testlib.feature import Feature
from testlib.proc import Tinc
from testlib.test import Test


TEST_DATA = b"foo bar baz"


def try_rsa_keys(priv_path: str, pub_path: str) -> None:
    """Check that RSA key pair works."""

    try:
        import cryptography  # type: ignore
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import padding  # type: ignore
    except ImportError:
        log.info("cryptography module missing or broken, skipping key checks")
        return

    version = cryptography.__version__.split(".", maxsplit=2)
    if not (int(version[0]) >= 3 and int(version[1]) >= 3):
        log.info("cryptography module is too old, skipping key check")
        return

    log.info("loading keys from (%s, %s)", priv_path, pub_path)
    with open(priv_path, "rb") as priv, open(pub_path, "rb") as pub:
        key_pair = (
            serialization.load_pem_private_key(priv.read(), password=None),
            serialization.load_pem_public_key(pub.read()),
        )

    s_pad = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    )
    s_hash = hashes.SHA256()

    log.info("signing sample data %s", TEST_DATA)
    signature = key_pair[0].sign(TEST_DATA, s_pad, s_hash)

    log.info("verifying signature %s", signature)
    key_pair[1].verify(signature, TEST_DATA, s_pad, s_hash)


def test_rsa(foo: Tinc) -> None:
    """Test command 'generate-rsa-keys'."""

    for key_size in "foobar", "512", "16384":
        log.info("generate %s-bit RSA key", key_size)
        _, err = foo.cmd("generate-rsa-keys", key_size, code=1)
        check.is_in("Invalid key size", err)

    log.info("generate RSA key with too many arguments")
    _, err = foo.cmd("generate-rsa-keys", "2048", "4096", code=1)
    check.is_in("Too many arguments", err)

    rsa_priv = foo.sub("rsa_key.priv")
    rsa_pub = foo.sub(f"hosts/{foo}")

    for key_size in "1024", "1025":
        log.info("generate %s-bit RSA key", key_size)
        _, err = foo.cmd("generate-rsa-keys", key_size)
        check.is_in("Generating 1024 bits", err)
        check.is_in("generating a weak", err)
        check.is_in("found and disabled", err)
        try_rsa_keys(rsa_priv, rsa_pub)

    for key_size in "2048", "2049":
        log.info("generate %s-bit RSA key", key_size)
        os.remove(rsa_priv)
        _, err = foo.cmd("generate-rsa-keys", key_size)
        check.is_in("Generating 2048 bits", err)
        check.file_exists(rsa_priv)
        try_rsa_keys(rsa_priv, rsa_pub)

    log.info("check that key is present")
    key = util.read_text(rsa_priv)
    check.has_prefix(key, "-----BEGIN RSA PRIVATE KEY-----")

    if RUN_ACCESS_CHECKS:
        log.info("remove access to private key")
        os.chmod(rsa_priv, 0)
        _, err = foo.cmd("generate-rsa-keys", "1024", code=1)
        check.is_in("Error opening file", err)


def test_rsa_nolegacy(foo: Tinc) -> None:
    """Test command 'generate-rsa-keys' on a nolegacy build."""

    log.info("generate RSA key with nolegacy tinc")
    _, err = foo.cmd("generate-rsa-keys", code=1)
    check.is_in("Unknown command", err)


def test_eddsa(foo: Tinc) -> None:
    """Test command 'generate-ed25519-keys'."""

    log.info("generate EC key with too many arguments")
    _, err = foo.cmd("generate-ed25519-keys", "2048", code=1)
    check.is_in("Too many arguments", err)

    log.info("generate and replace EC key")
    _, err = foo.cmd("generate-ed25519-keys")
    check.is_in("found and disabled", err)

    log.info("remove EC key files")
    ec_priv = foo.sub("ed25519_key.priv")
    ec_pub = foo.sub(f"hosts/{foo}")
    os.remove(ec_priv)
    os.remove(ec_pub)

    log.info("create new EC key files")
    foo.cmd("generate-ed25519-keys")
    check.has_prefix(util.read_text(ec_priv), "-----BEGIN ED25519 PRIVATE KEY-----")
    check.has_prefix(util.read_text(ec_pub), "Ed25519PublicKey")

    if RUN_ACCESS_CHECKS:
        log.info("remove access to EC private key file")
        os.chmod(ec_priv, 0)
        _, err = foo.cmd("generate-ed25519-keys", code=1)
        check.is_in("Error opening file", err)


def run_tests(foo: Tinc) -> None:
    """Run tests."""

    test_eddsa(foo)

    if Feature.LEGACY_PROTOCOL in foo.features:
        test_rsa(foo)
    else:
        test_rsa_nolegacy(foo)


with Test("run tests") as context:
    run_tests(context.node(init=True))
