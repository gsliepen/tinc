#!$PYTHON_PATH

import os
import sys
import multiprocessing.connection as mpc
import typing as T
import time
import signal

def on_error(*args):
    try:
        log.error('Uncaught exception', exc_info=args)
    except NameError:
        print('Uncaught exception', args)
    os.kill(0, signal.SIGTERM)

sys.excepthook = on_error

os.chdir(r'$CWD')
sys.path.append(r'$SRC_ROOT')

from testlib.proc import Tinc
from testlib.event import Notification
from testlib.log import new_logger
from testlib.const import MPC_FAMILY

this = Tinc('$NODE_NAME')
log = new_logger(this.name)

def notify_test(args: T.Dict[str, T.Any] = {}, error: T.Optional[Exception] = None):
    log.debug(f'sending notification to %s', $NOTIFICATIONS_ADDR)

    evt = Notification()
    evt.test = '$TEST_NAME'
    evt.node = '$NODE_NAME'
    evt.script = '$SCRIPT_NAME'
    evt.args = args
    evt.error = error

    for retry in range(1, 10):
        try:
            with mpc.Client($NOTIFICATIONS_ADDR, family=MPC_FAMILY, authkey=$AUTH_KEY) as conn:
                conn.send(evt)
            log.debug(f'sent notification')
            break
        except Exception as ex:
            log.error(f'notification failed', exc_info=ex)
            time.sleep(0.5)

try:
    log.debug('running user code')
$SCRIPT_SOURCE
    log.debug('user code finished')
except Exception as ex:
    log.error('user code failed', exc_info=ex)
    notify_test(error=ex)
    sys.exit(1)

notify_test()
