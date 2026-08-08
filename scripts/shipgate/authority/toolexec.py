"""ONE subprocess discipline for every trust tool this kit runs.

WHY THIS EXISTS. v4.1 ran cosign through `cosignexec._run`; v4.2 adds `gh attestation
verify`, and a second copy of the same subprocess wrapper is how the two copies drift — one
gets a timeout fix, the other keeps the bug. So the discipline lives here once and both
executors use it.

THE DISCIPLINE, in full, because each line is load-bearing:

  NO SHELL.          `shell=False` always. The argv is a list this package builds; nothing
                     target-controlled ever contributes an element.
  PINNED BINARY.     The executable is resolved from the verifier operator's own PATH or an
                     explicit SHIPGATE_*_BINARY variable, and the RESOLVED path is recorded
                     in the result — an audit must be able to say which bytes ran.
  MINIMAL ENV.       An allowlisted environment, built here. The target repository's
                     environment never leaks in. Which variable NAMES were passed is
                     recorded; values never are, because a credential in a log is a leak
                     with a timestamp.
  BOUNDED TIME.      A verification that hangs is an unknown, and an unknown is never a pass.
  BOUNDED OUTPUT.    A tool that printed a gigabyte is not evidence. stdout/stderr are
                     truncated at a fixed cap and the truncation is RECORDED, so a consumer
                     knows it is looking at a prefix — a silently truncated output could
                     hide the line that mattered.
  REAL RESULTS ONLY. The returned exit code is the process's own. There is no parameter for
                     a caller to supply an expected or captured exit code, and there never
                     will be: the operator asserting the answer is the exact hole the
                     executors exist to close.

This module is exempt from the subprocess import ban for the same reason `cosignexec` is
(see that module's docstring): it runs ONE pinned trust tool with argv built here, never
anything the target controls.
"""
import os
import shutil
import subprocess  # noqa: S404 - see the module docstring; same exemption as cosignexec
import time
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_TIMEOUT_SECONDS = 120

#: Nothing a trust tool legitimately prints is bigger than this (matches parsers._common).
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


class ToolExecError(Exception):
    """The tool could not be run, or did not finish. Never a verdict about evidence."""


class ToolBlocked(ToolExecError):
    """The tool is not available here. BLOCKED — distinct from a failed verification."""


def resolve_binary(default_name: str, env_var: str,
                   explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the tool binary: explicit path, then the operator's env var, then PATH.

    An explicit-or-env candidate that does not exist or is not executable resolves to None
    rather than silently falling through to PATH — an operator who named a binary meant THAT
    binary, and quietly running a different one is a substitution."""
    for candidate in (explicit, os.environ.get(env_var)):
        if candidate:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            return None
    return shutil.which(default_name)


def run(argv: Sequence[str], *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        cwd: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
        tool_name: str = "tool") -> Dict[str, Any]:
    """One invocation under the discipline above. Raises ToolBlocked/ToolExecError only for
    "could not run" conditions; a nonzero exit is a RESULT, not an exception."""
    argv = list(argv)
    env = {"PATH": os.environ.get("PATH", ""),
           "HOME": os.environ.get("HOME", "/tmp")}
    passed_names = []
    for name, value in (extra_env or {}).items():
        if value is not None:
            env[name] = value
            passed_names.append(name)
    started = time.time()
    try:
        proc = subprocess.run(  # noqa: S603 - pinned binary, argv built by this package
            argv, cwd=cwd, capture_output=True, timeout=timeout_seconds,
            shell=False, env=env)
    except FileNotFoundError as exc:
        raise ToolBlocked(f"{tool_name} could not be executed: {exc}")
    except subprocess.TimeoutExpired:
        raise ToolExecError(
            f"{tool_name} did not finish within {timeout_seconds}s; a verification that "
            f"hangs is an unknown, and an unknown is never a pass")
    except OSError as exc:
        raise ToolBlocked(f"{tool_name} could not be executed: {type(exc).__name__}: {exc}")

    stdout, stdout_truncated = _bound(proc.stdout)
    stderr, stderr_truncated = _bound(proc.stderr)
    return {
        "argv": argv,
        "executable": argv[0],
        "exitCode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdoutTruncated": stdout_truncated,
        "stderrTruncated": stderr_truncated,
        "envPassed": sorted(passed_names),
        "elapsedSeconds": round(time.time() - started, 3),
    }


def _bound(raw: Optional[bytes]):
    raw = raw or b""
    if len(raw) > MAX_OUTPUT_BYTES:
        return raw[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"), True
    return raw.decode("utf-8", "replace"), False


__all__ = ["DEFAULT_TIMEOUT_SECONDS", "MAX_OUTPUT_BYTES", "ToolBlocked", "ToolExecError",
           "resolve_binary", "run"]
