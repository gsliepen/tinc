#!/usr/bin/env python3

"""Run linters on project code. Add --fix to autofix files with linters that support it."""

import sys
import subprocess as subp
from glob import glob
from os import path, environ, chdir

DRY = "--fix" not in sys.argv or environ.get("CI")
HEADER = "#" * 24

if DRY:
    MSG = """
You're running linters in non-destructive readonly mode.
Some of them support automated fixes (like reformatting code).
To apply them, run `lint.py --fix` or `ninja -C build reformat`.
"""
    print(MSG, file=sys.stderr)

source_root = path.dirname(path.realpath(__file__))
source_root = environ.get("MESON_SOURCE_ROOT", source_root)
chdir(source_root)

# It's best not to use globs that cover everything in the project — if integration
# tests are run with a large --repeat value, test working directory can reach
# enormous sizes, and linters either get very slow, or start crashing.
linters = (
    [
        "astyle",
        "--recursive",
        "--options=.astylerc",
        "--dry-run" if DRY else "--formatted",
        "./*.c",
        "./*.h",
    ],
    ["shfmt", "-d" if DRY else "-w", "-i", "2", "-s", "."],
    ["black", "--check" if DRY else ".", "."],
    ["pylint", "."],
    ["mypy", "--exclude", "build", "."],
    ["shellcheck", "-x", *glob(".ci/**/*.sh", recursive=True)],
    ["markflow", "--line-length", "80", "--check" if DRY else "--verbose", ".", ".ci"],
)

failed: bool = False

for cmd in linters:
    exe = cmd[0]
    print(f"{HEADER} Running linter '{exe}' {HEADER}")

    try:
        res = subp.run(
            cmd,
            check=False,
            stdout=subp.PIPE,
            encoding="utf-8",
        )
        failed = (
            failed
            or bool(res.returncode)
            or (exe == "astyle" and "Formatted  " in res.stdout)
        )
        print(res.stdout)
    except FileNotFoundError as e:
        print(f"Warning: linter {exe} is missing", file=sys.stderr)

sys.exit(int(failed))
