"""Global logger for using in test and tincd scripts."""

import logging
import os
import sys
import typing as T
from types import TracebackType

from .path import TEST_WD, TEST_NAME

logging.basicConfig(level=logging.DEBUG)

_fmt = logging.Formatter(
    "%(asctime)s %(name)s %(filename)s:%(lineno)d %(levelname)s %(message)s"
)

# Where to put log files for this test and nodes started by it
_log_dir = os.path.join(TEST_WD, "logs")


def new_logger(name: str) -> logging.Logger:
    """Create a new named logger with common logging format.
    Log entries will go into a separate logfile named 'name.log'.
    """
    os.makedirs(_log_dir, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    file = logging.FileHandler(os.path.join(_log_dir, name + ".log"))
    file.setFormatter(_fmt)
    logger.addHandler(file)

    return logger


# Main logger used by most tests
log = new_logger(TEST_NAME)


def _exc_hook(
    ex_type: T.Type[BaseException],
    base: BaseException,
    tb_type: T.Optional[TracebackType],
) -> None:
    """Logging handler for uncaught exceptions."""
    log.error("Uncaught exception", exc_info=(ex_type, base, tb_type))


sys.excepthook = _exc_hook
