#!/usr/bin/env python3

"""Print current tinc version for using in build scripts.

First try to determine the latest version using git tags. If this fails (because
the .git directory is missing, git is not installed, or for some other reason),
fall back to using the VERSION file. If it is not present or could not be read,
use 'unknown'.
"""

from os import path, environ
from sys import argv, stderr
import subprocess as subp
import typing as T

PREFIX = "release-"
SOURCE_ROOT = path.dirname(path.realpath(__file__))
SOURCE_ROOT = environ.get("MESON_SOURCE_ROOT", SOURCE_ROOT)

cmd = [
    "git",
    "--git-dir",
    path.join(SOURCE_ROOT, ".git"),
    "describe",
    "--always",
    "--tags",
    "--match=" + PREFIX + "*",
]

if "short" in argv:
    cmd.append("--abbrev=0")

version: T.Optional[str] = None

try:
    result = subp.run(cmd, stdout=subp.PIPE, encoding="utf-8", check=False)
    if not result.returncode:
        version = result.stdout
except FileNotFoundError:
    pass

if not version:
    try:
        with open(path.join(SOURCE_ROOT, "VERSION"), "r", encoding="utf-8") as f:
            version = f.read().strip()
    except OSError as e:
        print("could not read version from file", e, file=stderr)
elif version.startswith(PREFIX):
    version = version[len(PREFIX) :].strip()

print(version if version else "unknown", end="")
