"""Classes for working with compiled instances of tinc and tincd binaries."""

import os
import random
import tempfile
import typing as T
import subprocess as subp
from enum import Enum
from platform import system

from . import check, path
from .log import log
from .script import TincScript, Script, ScriptType
from .template import make_script, make_cmd_wrap
from .util import random_string, random_port

# Does the OS support all addresses in 127.0.0.0/8 without additional configuration?
_FULL_LOCALHOST_SUBNET = system() in ("Linux", "Windows")

# Path to the system temporary directory.
_TEMPDIR = tempfile.gettempdir()


def _make_wd(name: str) -> str:
    work_dir = os.path.join(path.TEST_WD, "data", name)
    os.makedirs(work_dir, exist_ok=True)
    return work_dir


def _random_octet() -> int:
    return random.randint(1, 254)


def _rand_localhost() -> str:
    """Generate random IP in subnet 127.0.0.0/8 for operating systems that support
    it without additional configuration. For all others, return 127.0.0.1.
    """
    if _FULL_LOCALHOST_SUBNET:
        return f"127.{_random_octet()}.{_random_octet()}.{_random_octet()}"
    return "127.0.0.1"


class Feature(Enum):
    """Optional features supported by both tinc and tincd."""

    COMP_LZ4 = "comp_lz4"
    COMP_LZO = "comp_lzo"
    COMP_ZLIB = "comp_zlib"
    CURSES = "curses"
    JUMBOGRAMS = "jumbograms"
    LEGACY_PROTOCOL = "legacy_protocol"
    LIBGCRYPT = "libgcrypt"
    MINIUPNPC = "miniupnpc"
    OPENSSL = "openssl"
    READLINE = "readline"
    SANDBOX = "sandbox"
    TUNEMU = "tunemu"
    UML = "uml"
    VDE = "vde"
    WATCHDOG = "watchdog"


class Tinc:
    """Thin wrapper around Popen that simplifies running tinc/tincd
    binaries by passing required arguments, checking exit codes, etc.
    """

    name: str
    address: str
    _work_dir: str
    _pid: T.Optional[int]
    _port: T.Optional[int]
    _scripts: T.Dict[str, TincScript]
    _procs: T.List[subp.Popen]

    def __init__(self, name: str = "", addr: str = "") -> None:
        self.name = name if name else random_string(10)
        self.address = addr if addr else _rand_localhost()
        self._work_dir = _make_wd(self.name)
        os.makedirs(self._work_dir, exist_ok=True)
        self._port = None
        self._scripts = {}
        self._procs = []

    def randomize_port(self) -> int:
        """Use a random port for this node."""
        self._port = random_port()
        return self._port

    @property
    def pid_file(self) -> str:
        """Get the path to the pid file."""
        return os.path.join(_TEMPDIR, f"tinc_{self.name}")

    def read_port(self) -> int:
        """Read port used by tincd from its pidfile and update the _port field."""
        log.debug("reading pidfile at %s", self.pid_file)

        with open(self.pid_file, "r", encoding="utf-8") as f:
            content = f.read()
        log.debug("found data %s", content)

        pid, _, _, token, port = content.split()
        check.equals("port", token)

        self._port = int(port)
        self._pid = int(pid)
        return self._port

    @property
    def port(self) -> int:
        """Port that tincd is listening on."""
        assert self._port is not None
        return self._port

    @property
    def pid(self) -> int:
        """pid of the main tincd process."""
        assert self._pid is not None
        return self._pid

    def __str__(self) -> str:
        return self.name

    def __getitem__(self, script: ScriptType) -> TincScript:
        if isinstance(script, Script):
            script = script.name
        return self._scripts[script]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    @property
    def features(self) -> T.List[Feature]:
        """List of features supported by tinc and tincd."""
        tinc, _ = self.cmd("--version")
        tincd, _ = self.tincd("--version").communicate(timeout=5)
        prefix, features = "Features: ", []

        for out in tinc, tincd:
            for line in out.splitlines():
                if not line.startswith(prefix):
                    continue
                tokens = line[len(prefix) :].split()
                for token in tokens:
                    features.append(Feature(token))
                break

        log.info('supported features: "%s"', features)
        return features

    @property
    def _common_args(self) -> T.List[str]:
        return [
            "--net",
            self.name,
            "--config",
            self.work_dir,
            "--pidfile",
            self.pid_file,
        ]

    def sub(self, *paths: str) -> str:
        """Return path to a subdirectory within the working dir for this node."""
        return os.path.join(self._work_dir, *paths)

    @property
    def work_dir(self):
        """Node's working directory."""
        return self._work_dir

    @property
    def script_up(self) -> str:
        """Name of the hosts/XXX-up script for this node."""
        return f"hosts/{self.name}-up"

    @property
    def script_down(self) -> str:
        """Name of the hosts/XXX-down script for this node."""
        return f"hosts/{self.name}-down"

    def cleanup(self) -> None:
        """Terminate all tinc and tincd processes started from this instance."""
        log.info("running node cleanup for %s", self)

        try:
            self.cmd("stop")
        except (AssertionError, ValueError):
            log.info("unsuccessfully tried to stop node %s", self)

        for proc in self._procs:
            if proc.returncode is not None:
                log.debug("PID %d exited, skipping", proc.pid)
            else:
                log.info("PID %d still running, stopping", proc.pid)
                try:
                    proc.kill()
                except OSError as ex:
                    log.error("could not kill PID %d", proc.pid, exc_info=ex)

            log.debug("waiting on %d to prevent zombies", proc.pid)
            try:
                proc.wait()
            except OSError as ex:
                log.error("waiting on %d failed", proc.pid, exc_info=ex)

        self._procs.clear()

    def start(self, *args: str) -> int:
        """Start the node, wait for it to call tinc-up, and get the port it's
        listening on from the pid file. Don't use this method unless you need
        to know the port tincd is running on. Call .cmd("start"), it's faster.

        Reading pidfile and setting the port cannot be done from tinc-up because
        you can't send tinc commands to yourself there — the daemon doesn't
        respond to them until tinc-up is finished. The port field on this Tinc
        instance is updated to reflect the correct port. If tinc-up is missing,
        this command creates a new one, and then disables it.
        """
        new_script = Script.TINC_UP.name not in self._scripts
        if new_script:
            self.add_script(Script.TINC_UP)

        tinc_up = self[Script.TINC_UP]
        self.cmd(*args, "start", "--logfile", self.sub("log"))
        tinc_up.wait()

        if new_script:
            tinc_up.disable()

        self._port = self.read_port()
        self.cmd("set", "Port", str(self._port))

        return self._port

    def cmd(
        self,
        *args: str,
        code: T.Optional[int] = 0,
        stdin: T.Optional[T.AnyStr] = None,
        timeout: T.Optional[int] = None,
    ) -> T.Tuple[str, str]:
        """Run command through tinc, writes `stdin` to it (if the argument is not None),
        check its return code (if the argument is not None), and return (stdout, stderr).
        """
        proc = self.tinc(*args, binary=isinstance(stdin, bytes))
        log.debug('tinc %s: PID %d, in "%s", want code %s', self, proc.pid, stdin, code)

        out, err = proc.communicate(stdin, timeout=60 if timeout is None else timeout)
        res = proc.returncode
        self._procs.remove(proc)
        log.debug('tinc %s: code %d, out "%s", err "%s"', self, res, out, err)

        if code is not None:
            check.equals(code, res)

        return out if out else "", err if err else ""

    def tinc(self, *args: str, binary=False) -> subp.Popen:
        """Start tinc with the specified arguments."""
        args = tuple(filter(bool, args))
        cmd = [path.TINC_PATH, *self._common_args, *args]
        log.debug('starting tinc %s: "%s"', self.name, " ".join(cmd))
        # pylint: disable=consider-using-with
        proc = subp.Popen(
            cmd,
            cwd=self._work_dir,
            stdin=subp.PIPE,
            stdout=subp.PIPE,
            stderr=subp.PIPE,
            encoding=None if binary else "utf-8",
        )
        self._procs.append(proc)
        return proc

    def tincd(self, *args: str, env: T.Optional[T.Dict[str, str]] = None) -> subp.Popen:
        """Start tincd with the specified arguments."""
        args = tuple(filter(bool, args))
        cmd = [
            path.TINCD_PATH,
            *self._common_args,
            "--logfile",
            self.sub("log"),
            "-d5",
            *args,
        ]
        log.debug('starting tincd %s: "%s"', self.name, " ".join(cmd))
        if env is not None:
            env = {**os.environ, **env}
        # pylint: disable=consider-using-with
        proc = subp.Popen(
            cmd,
            cwd=self._work_dir,
            stdin=subp.PIPE,
            stdout=subp.PIPE,
            stderr=subp.PIPE,
            encoding="utf-8",
            env=env,
        )
        self._procs.append(proc)
        return proc

    def add_script(self, script: ScriptType, source: str = "") -> TincScript:
        """Create a script with the passed Python source code.
        The source must either be empty, or start indentation with 4 spaces.
        If the source is empty, the created script can be used to receive notifications.
        """
        rel_path = script if isinstance(script, str) else script.value
        check.not_in(rel_path, self._scripts)

        full_path = os.path.join(self._work_dir, rel_path)
        tinc_script = TincScript(self.name, rel_path, full_path)

        log.debug("creating script %s at %s", script, full_path)
        with open(full_path, "w", encoding="utf-8") as f:
            content = make_script(self.name, rel_path, source)
            f.write(content)

        if os.name == "nt":
            log.debug("creating .cmd script wrapper at %s", full_path)
            win_content = make_cmd_wrap(full_path)
            with open(f"{full_path}.cmd", "w", encoding="utf-8") as f:
                f.write(win_content)
        else:
            os.chmod(full_path, 0o755)

        if isinstance(script, Script):
            self._scripts[script.name] = tinc_script
        self._scripts[rel_path] = tinc_script

        return tinc_script
