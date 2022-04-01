#!/usr/bin/env python3

from os import path, environ
from sys import argv, stderr
import subprocess as subp

prefix = "release-"
source_root = path.dirname(path.realpath(__file__))
source_root = environ.get("MESON_SOURCE_ROOT", source_root)

cmd = [
    "git",
    "--git-dir",
    path.join(source_root, ".git"),
    "describe",
    "--always",
    "--tags",
    "--match=" + prefix + "*",
]

if "short" in argv:
    cmd.append("--abbrev=0")

version = None

try:
    result = subp.run(cmd, stdout=subp.PIPE, encoding="utf-8")
    if not result.returncode:
        version = result.stdout
except FileNotFoundError:
    pass

if not version:
    try:
        with open(path.join(source_root, "VERSION"), "r") as f:
            version = f.read().strip()
    except OSError as e:
        print("could not read version from file", e, file=stderr)
elif version.startswith(prefix):
    version = version[len(prefix):].strip()

print(version if version else "unknown", end="")
