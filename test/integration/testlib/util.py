"""Miscellaneous utility functions."""

import os
import sys
import subprocess as subp
import random
import string
import socket
import typing as T
import tempfile
from pathlib import Path

from . import check
from .log import log
from .const import EXIT_SKIP

_ALPHA_NUMERIC = string.ascii_lowercase + string.digits


def random_port() -> int:
    """Return an unused TCP port in the unprivileged range.
    Note that this function releases the port before returning, and it can be
    overtaken by something else before you use it.
    """
    while True:
        port = random.randint(1024, 65535)
        try:
            with socket.socket() as sock:
                sock.bind(("0.0.0.0", port))
                sock.listen()
            return port
        except OSError as ex:
            log.debug("could not bind to random port %d", port, exc_info=ex)


def temp_file(content: str) -> str:
    """Create a temporary file and write text content into it."""
    file = tempfile.mktemp()
    with open(file, "w", encoding="utf-8") as f:
        f.write(content)
    return file


def remove_file(path: T.Union[str, Path]) -> bool:
    """Try to remove file without failing if it does not exist."""
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


def random_string(k: int) -> str:
    """Generate a random alphanumeric string of length k."""
    return "".join(random.choices(_ALPHA_NUMERIC, k=k))


def find_line(filename: str, prefix: str) -> str:
    """Find a line with the prefix in a text file.
    Check that only one line matches.
    """
    with open(filename, "r", encoding="utf-8") as f:
        keylines = [line for line in f.readlines() if line.startswith(prefix)]
    check.equals(1, len(keylines))
    return keylines[0].rstrip()


def require_root() -> None:
    """Check that test is running with root privileges.
    Exit with code 77 otherwise.
    """
    euid = os.geteuid()
    if euid:
        log.info("this test requires root (but running under UID %d)", euid)
        sys.exit(EXIT_SKIP)


def require_command(*args: str) -> None:
    """Check that command args runs with exit code 0.
    Exit with code 77 otherwise.
    """
    try:
        if subp.run(args, check=False).returncode == 0:
            return
    except FileNotFoundError:
        pass
    log.info('this test requires command "%s" to work', " ".join(args))
    sys.exit(EXIT_SKIP)


def require_path(path: str) -> None:
    """Check that path exists in your file system.
    Exit with code 77 otherwise.
    """
    if not os.path.exists(path):
        log.warning("this test requires path %s to be present", path)
        sys.exit(EXIT_SKIP)


# Thin wrappers around `with open(...) as f: f.do_something()`
# Don't do much, besides saving quite a bit of space because of how frequently they're needed.


def read_text(path: str) -> str:
    """Return the text contents of a file."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_text(path: str, text: str) -> str:
    """Write text to a file, replacing its content. Return the text added."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def read_lines(path: str) -> T.List[str]:
    """Read file as a list of lines."""
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def write_lines(path: str, lines: T.List[str]) -> T.List[str]:
    """Write text lines to a file, replacing it content. Return the line added."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(os.linesep.join(lines))
        f.write(os.linesep)
    return lines


def append_line(path: str, line: str) -> str:
    """Append a line to the end of the file. Return the line added."""
    line = f"{os.linesep}{line}{os.linesep}"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
    return line
