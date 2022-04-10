"""Some hardcoded constants."""

import os

# Exit code to skip current test
EXIT_SKIP = 77

# Family name for multiprocessing Listener/Connection
MPC_FAMILY = "AF_PIPE" if os.name == "nt" else "AF_UNIX"
