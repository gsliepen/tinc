#!/usr/bin/env python3

from os import path, environ
from sys import stderr
import subprocess as subp
import glob

source_root = path.dirname(path.realpath(__file__))
source_root = environ.get("MESON_SOURCE_ROOT", source_root)

astyle_cmd = [
    "astyle",
    "--options=.astylerc",
    "--recursive",
    "*.c",
    "*.h",
]

shfmt_cmd = [
    "shfmt",
    "-i", "2",
    "-s",
    "-w",
]

for path in "**/*.sh", "**/*.test", ".ci/**/*.sh":
    shfmt_cmd.extend(glob.glob(path, root_dir=source_root, recursive=True))

for cmd in astyle_cmd, shfmt_cmd:
    try:
        result = subp.run(cmd, cwd=source_root, check=True)
    except FileNotFoundError as e:
        print("Warning: missing", cmd[0], file=stderr)
