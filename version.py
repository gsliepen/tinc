#!/usr/bin/env python3

from sys import argv, exit
import subprocess as subp

prefix = "release-"

cmd = [
    "git",
    "describe",
    "--always",
    "--tags",
    "--match=" + prefix + "*",
]

if "short" in argv:
    cmd.append("--abbrev=0")

result = subp.run(cmd, stdout=subp.PIPE, encoding="utf-8")
version = result.stdout

if not result.returncode and version and version.startswith(prefix):
    version = version[len(prefix):].strip()

print(version if version else "unknown", end="")
exit(not version)
