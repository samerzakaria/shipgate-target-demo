"""The single execution adapter.

EVERY target-controlled process — the repo's install, build, boot, test, mutation, fault,
probe and synthetic commands — goes through `ExecutionAdapter.run_target`. Nothing else in
the codebase may call `subprocess` on target-controlled input; `tests/boundary/` proves it
by AST-scanning the tree.

Guarantees, in the order they are applied:

  1. CONTAINMENT FIRST. The boundary is resolved and proved before a child is spawned. If
     the policy requires containment and none was proved, `ContainmentUnavailable` is
     raised. There is NO unrestricted fallback — the v3.8 path that printed
     "running WITHOUT a sandbox" and continued does not exist here.
  2. WORKING DIRECTORY. `cwd` must exist, must be a directory, and must resolve inside the
     declared run area. A collector cannot run target code against the user's real tree.
  3. ENVIRONMENT. Built by allowlist (see env.py).
  4. TIMEOUT. Always set; there is no `timeout=None` path.
  5. OUTPUT LIMIT. stdout/stderr are streamed to disk with a hard byte cap; exceeding it
     terminates the process and is reported as a result, not an exception, so a repo cannot
     OOM the gate by printing.
  6. PROCESS TREE. The child is started in a new session and the whole process GROUP is
     killed on timeout or overflow, so dev servers and watchers cannot orphan.
  7. LEDGERED. Every invocation is appended to an in-memory ledger that becomes the
     CONTAINMENT evidence, which is what makes "all target processes were contained" a
     checkable claim.
"""
import dataclasses
import errno
import os
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

from ..util.canonical import digest_of
from ..util.clock import utcnow_iso
from . import containment as _containment
from .containment import ContainmentUnavailable
from .env import build_env, leaked_names

#: Sentinel exit codes the adapter itself assigns. Chosen outside the 0-125 range a normal
#: command uses so they are never confused with the target's own status.
RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127


class ExecutionRefused(RuntimeError):
    """The adapter refused to run a command. Never a partial execution."""


@dataclasses.dataclass(frozen=True)
class ExecResult:
    argv: Tuple[str, ...]
    display: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    output_truncated: bool
    containment_kind: str
    contained: bool
    cwd: str
    started_at: str
    is_target_code: bool

    @property
    def ok(self):
        return self.returncode == 0 and not self.timed_out and not self.output_truncated

    def to_json(self, include_output=False):
        d = {
            "display": self.display,
            "returncode": self.returncode,
            "durationMs": self.duration_ms,
            "timedOut": self.timed_out,
            "outputTruncated": self.output_truncated,
            "containmentKind": self.containment_kind,
            "contained": self.contained,
            "startedAt": self.started_at,
            "isTargetCode": self.is_target_code,
        }
        if include_output:
            d["stdout"] = self.stdout
            d["stderr"] = self.stderr
        return d


class ExecutionAdapter:
    """Containment-aware execution chokepoint.

    Construct one per run and hand it to every collector. Collectors never construct their
    own, so the run-area confinement and the ledger are global to the run.
    """

    def __init__(self, run_area, policy, containment_record=None, allow_env=()):
        self.run_area = Path(run_area).resolve()
        if not self.run_area.is_dir():
            raise ExecutionRefused(f"run area does not exist or is not a directory: {self.run_area}")
        self.policy = policy
        # Operator-forwarded parent-environment names, applied to EVERY invocation so no
        # collector has to know about them. Secret-shaped names are still refused by
        # `env.build_env`, so forwarding cannot leak a signing key.
        self.allow_env = tuple(n for n in allow_env if n)
        self._ledger = []
        self._containment = containment_record or _containment.detect(
            accepted=tuple(policy.containment.accepted))
        self._boundary_checked = False

    # --- containment -------------------------------------------------------------------
    @property
    def containment(self):
        return dict(self._containment)

    @property
    def contained(self):
        return bool(self._containment.get("established"))

    def require_boundary(self):
        """Resolve the containment question once, up front, and fail closed.

        Called automatically before the first target execution, and callable directly so a
        caller can refuse early rather than after twenty minutes of collection.
        """
        if self._boundary_checked:
            return self._containment["kind"]
        cp = self.policy.containment
        if self.contained:
            self._boundary_checked = True
            return self._containment["kind"]
        if not cp.required:
            self._boundary_checked = True
            return "none"
        if cp.allow_host_exec:
            # Explicit, audited operator consent. Containment stays NOT established, so the
            # decision records an uncontained run and `containment.enforced` fails — this is
            # a consent flag, never a boundary and never a bypass.
            self._boundary_checked = True
            return "host-acknowledged"
        raise ContainmentUnavailable(
            "REFUSING to execute target-controlled code with no proved containment boundary. "
            f"{_containment.describe(self._containment)} "
            "Establish one (SHIPGATE_EXEC_MODE=container with SHIPGATE_RUNNER_IMAGE, or a "
            "working bwrap), or set SHIPGATE_ALLOW_HOST_EXEC=1 to accept host-execution risk "
            "— which is recorded in the decision and makes the containment check FAIL.",
            detail=self._containment,
        )

    # --- wrapping ----------------------------------------------------------------------
    def _wrap(self, argv, cwd, network):
        """Wrap argv in the proved boundary. Returns argv unchanged only when there is no
        boundary AND host exec was explicitly acknowledged."""
        kind = self._containment.get("kind")
        detail = self._containment.get("detail") or {}
        cwd = str(Path(cwd).resolve())
        net = "none" if not network else (os.environ.get("SHIPGATE_CONTAINER_NET") or "bridge")

        if kind == "container":
            engine = detail.get("enginePath") or _which_engine(detail.get("engine"))
            image = detail.get("image")
            if not engine or not image:
                raise ContainmentUnavailable(
                    "container boundary was proved but engine/image are no longer resolvable",
                    detail=self._containment)
            return [
                engine, "run", "--rm",
                f"--network={net}", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "512", "--memory", "4g", "--memory-swap", "4g", "--cpus", "2",
                "--user", "1000:1000",
                "-v", f"{cwd}:/work", "-w", "/work",
                image, *argv,
            ]

        if kind == "bwrap":
            import shutil
            bwrap = shutil.which("bwrap")
            if not bwrap:
                raise ContainmentUnavailable("bwrap boundary was proved but bwrap vanished",
                                             detail=self._containment)
            args = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid",
                    "--unshare-ipc", "--unshare-uts",
                    "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                    "--tmpfs", "/tmp",
                    "--bind", cwd, cwd]
            if not network:
                args.insert(1, "--unshare-net")
            # The gate's own state must be read-only to target code: a target test that can
            # rewrite the seal, the ledger or the spec baseline defeats the anti-fake core.
            wd = self.run_area / "shipgate-workdir"
            if wd.exists():
                args += ["--ro-bind", str(wd), str(wd)]
            args += ["--chdir", cwd, "--"] + list(argv)
            return args

        # No boundary. Only reachable with explicit acknowledgment (require_boundary would
        # otherwise have raised). unshare is applied when available purely to deny egress —
        # it is hardening, and `contained` stays False.
        if "unshare" in (self._containment.get("hardening") or []) and not network:
            import shutil
            un = shutil.which("unshare")
            if un:
                return [un, "-Umn", "--", *argv]
        return list(argv)

    # --- execution ---------------------------------------------------------------------
    def run_target(self, argv=None, *, command=None, cwd=None, timeout=None, env_extra=None,
                   allow_env=(), network=False, label=None, is_target_code=True):
        """Run a target-controlled process. The only supported way to do so.

        Exactly one of `argv` (a list, no shell) or `command` (a string, run under
        `/bin/sh -c` because the user authored it as a shell command) must be given.
        """
        if (argv is None) == (command is None):
            raise ExecutionRefused("pass exactly one of argv= or command=")

        if is_target_code:
            self.require_boundary()

        cwd = self._resolve_cwd(cwd)
        timeout = int(timeout or self.policy.containment.default_timeout_seconds)
        if timeout <= 0:
            raise ExecutionRefused("timeout must be a positive number of seconds")

        if command is not None:
            inner = ["/bin/sh", "-c", command]
            display = command
        else:
            inner = [str(a) for a in argv]
            display = " ".join(shlex.quote(a) for a in inner)

        env = build_env(extra=env_extra,
                        allow_extra_names=tuple(allow_env) + self.allow_env)
        wrapped = self._wrap(inner, cwd, network) if is_target_code else inner

        started = utcnow_iso()
        t0 = time.monotonic()
        result = self._spawn(wrapped, cwd, timeout, env)
        duration = int((time.monotonic() - t0) * 1000)

        res = ExecResult(
            argv=tuple(inner),
            display=label or display,
            returncode=result["rc"],
            stdout=result["stdout"],
            stderr=result["stderr"],
            duration_ms=duration,
            timed_out=result["timed_out"],
            output_truncated=result["truncated"],
            containment_kind=self._containment.get("kind", "none"),
            contained=self.contained,
            cwd=str(cwd),
            started_at=started,
            is_target_code=is_target_code,
        )
        self._ledger.append(res)
        return res

    def run_internal(self, argv, *, cwd=None, timeout=120, env_extra=None, allow_env=()):
        """Run a GATE-OWNED command (git, the gate's own python helpers).

        This is not the untrusted-code path: the gate authored the argv and the binary is
        not target-controlled, so containment is not required. It is still ledgered,
        timeout-bounded and output-capped, and it still refuses a shell string — so it
        cannot be used to smuggle target-controlled input past the boundary.
        """
        if isinstance(argv, str):
            raise ExecutionRefused(
                "run_internal takes an argv list, never a shell string — a string would let "
                "target-controlled text reach a shell without containment")
        return self.run_target(argv=argv, cwd=cwd, timeout=timeout, env_extra=env_extra,
                               allow_env=allow_env, is_target_code=False)

    # --- internals ---------------------------------------------------------------------
    def _resolve_cwd(self, cwd):
        p = (self.run_area if cwd is None else Path(cwd)).resolve()
        if not p.is_dir():
            raise ExecutionRefused(f"working directory does not exist: {p}")
        try:
            p.relative_to(self.run_area)
        except ValueError:
            raise ExecutionRefused(
                f"refusing to execute outside the run area: cwd={p} runArea={self.run_area}"
            ) from None
        return p

    def _spawn(self, argv, cwd, timeout, env):
        cap = int(self.policy.containment.max_output_bytes)
        with tempfile.TemporaryDirectory(prefix="shipgate-exec-") as tmp:
            out_p = Path(tmp) / "stdout"
            err_p = Path(tmp) / "stderr"
            try:
                with open(out_p, "wb") as fo, open(err_p, "wb") as fe:
                    proc = subprocess.Popen(
                        argv, cwd=str(cwd), env=env, stdout=fo, stderr=fe,
                        stdin=subprocess.DEVNULL, start_new_session=True, close_fds=True)
            except OSError as exc:
                msg = f"failed to spawn {argv[0]!r}: {exc.strerror or exc}"
                if exc.errno == errno.ENOENT:
                    msg += " (not found on PATH inside the boundary)"
                return {"rc": RC_SPAWN_FAILED, "stdout": "", "stderr": msg,
                        "timed_out": False, "truncated": False}

            deadline = time.monotonic() + timeout
            truncated = timed_out = False
            while True:
                if proc.poll() is not None:
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                if (_size(out_p) + _size(err_p)) > cap:
                    truncated = True
                    break
                time.sleep(0.05)

            if timed_out or truncated:
                _kill_tree(proc)

            rc = proc.returncode
            if rc is None:
                rc = RC_TIMEOUT if timed_out else RC_OUTPUT_LIMIT
            elif timed_out:
                rc = RC_TIMEOUT
            elif truncated:
                rc = RC_OUTPUT_LIMIT

            stdout = _read_capped(out_p, cap)
            stderr = _read_capped(err_p, cap)
            if timed_out:
                stderr += f"\nship-gate: killed after {timeout}s (process group terminated)"
            if truncated:
                stderr += (f"\nship-gate: killed after exceeding the {cap}-byte output limit "
                           "(process group terminated)")
            return {"rc": rc, "stdout": stdout, "stderr": stderr,
                    "timed_out": timed_out, "truncated": truncated}

    # --- evidence ----------------------------------------------------------------------
    @property
    def ledger(self):
        return tuple(self._ledger)

    def containment_payload(self):
        """The payload behind the CONTAINMENT evidence.

        `allTargetContained` is the load-bearing field: it is False if ANY target-code
        invocation ran without a proved boundary, which is what the `containment.enforced`
        check reads.
        """
        target = [r for r in self._ledger if r.is_target_code]
        uncontained = [r for r in target if not r.contained]
        return {
            "boundary": self._containment,
            "description": _containment.describe(self._containment),
            "hostExecAcknowledged": bool(self.policy.containment.allow_host_exec),
            "containmentRequired": bool(self.policy.containment.required),
            "targetInvocations": len(target),
            "internalInvocations": len(self._ledger) - len(target),
            "uncontainedTargetInvocations": len(uncontained),
            "allTargetContained": len(target) > 0 and not uncontained,
            "anyTargetExecuted": len(target) > 0,
            "timeouts": sum(1 for r in self._ledger if r.timed_out),
            "outputLimitHits": sum(1 for r in self._ledger if r.output_truncated),
            "secretsWithheld": leaked_names(build_env()),
            "invocations": [r.to_json() for r in self._ledger],
            "ledgerDigest": digest_of([r.to_json() for r in self._ledger]),
        }


def _which_engine(name):
    import shutil
    if name:
        p = shutil.which(name)
        if p:
            return p
    return shutil.which("docker") or shutil.which("podman")


def _size(p):
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _read_capped(p, cap):
    try:
        with open(p, "rb") as fh:
            data = fh.read(cap)
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


def _kill_tree(proc):
    """SIGTERM then SIGKILL the whole process GROUP, so spawned servers cannot orphan."""
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except OSError:
            pass
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if proc.poll() is not None:
                return
            time.sleep(0.05)
    try:
        proc.wait(timeout=1)
    except subprocess.SubprocessError:
        pass
