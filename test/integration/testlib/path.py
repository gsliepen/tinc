"""Paths to compiled binaries, and a few other important environment variables."""

import os
import pathlib
import sys

env = {
    "TEST_NAME": os.getenv("TEST_NAME"),
    "TINC_PATH": os.getenv("TINC_PATH"),
    "TINCD_PATH": os.getenv("TINCD_PATH"),
    "SPLICE_PATH": os.getenv("SPLICE_PATH"),
    "PYTHON_PATH": os.getenv("PYTHON_PATH"),
    "SPTPS_TEST_PATH": os.getenv("SPTPS_TEST_PATH"),
    "SPTPS_KEYPAIR_PATH": os.getenv("SPTPS_KEYPAIR_PATH"),
}

# Not strictly necessary, used for better autocompletion and search by reference.
TEST_NAME = str(env["TEST_NAME"])
TINC_PATH = str(env["TINC_PATH"])
TINCD_PATH = str(env["TINCD_PATH"])
SPLICE_PATH = str(env["SPLICE_PATH"])
PYTHON_PATH = str(env["PYTHON_PATH"])
SPTPS_TEST_PATH = str(env["SPTPS_TEST_PATH"])
SPTPS_KEYPAIR_PATH = str(env["SPTPS_KEYPAIR_PATH"])

PYTHON_CMD = "runpython" if "meson.exe" in PYTHON_PATH.lower() else ""
PYTHON_INTERPRETER = f"{PYTHON_PATH} {PYTHON_CMD}".rstrip()


def _check() -> bool:
    """Basic sanity checks on passed environment variables."""
    for key, val in env.items():
        if not val or (key != "TEST_NAME" and not os.path.isfile(val)):
            return False
    return True


if not _check():
    MSG = """
Please run tests using
    $ meson test -C build
or
    $ ninja -C build test
"""
    print(MSG, file=sys.stderr)
    sys.exit(1)

# Current working directory
CWD = os.getcwd()

# Path to the testing library
TESTLIB_ROOT = pathlib.Path(__file__).parent

# Source root for the integration test suite
TEST_SRC_ROOT = TESTLIB_ROOT.parent.resolve()

_wd = os.path.join(CWD, "wd")
os.makedirs(_wd, exist_ok=True)

# Useful when running tests manually
_gitignore = os.path.join(_wd, ".gitignore")
if not os.path.exists(_gitignore):
    with open(_gitignore, "w", encoding="utf-8") as f:
        f.write("*")

# Working directory for this test
TEST_WD = os.path.join(_wd, TEST_NAME)
