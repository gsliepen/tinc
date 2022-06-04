#!/usr/bin/env python3

"""Basic sanity checks on compiled executables."""

from subprocess import run, PIPE

from testlib import path, check
from testlib.log import log

for exe in (
    path.TINC_PATH,
    path.TINCD_PATH,
    path.SPTPS_TEST_PATH,
    path.SPTPS_KEYPAIR_PATH,
):
    cmd = [exe, "--help"]
    log.info('testing command "%s"', cmd)
    res = run(cmd, stdout=PIPE, stderr=PIPE, encoding="utf-8", timeout=10, check=False)
    check.success(res.returncode)
    check.is_in("Usage:", res.stdout, res.stderr)
