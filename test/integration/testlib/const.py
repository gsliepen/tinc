"""Some hardcoded constants."""

import os

# Exit code to skip current test
EXIT_SKIP = 77

# Family name for multiprocessing Listener/Connection
MPC_FAMILY = "AF_PIPE" if os.name == "nt" else "AF_UNIX"

# Do access checks on files. Disabled when not available or not applicable.
RUN_ACCESS_CHECKS = os.name != "nt" and os.geteuid() != 0

# Copy of the same define from net.h
MAXSOCKETS = 8
