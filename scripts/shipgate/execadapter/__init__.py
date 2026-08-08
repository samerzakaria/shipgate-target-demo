"""The one place target-controlled processes are spawned.

Depends on: shipgate.models, shipgate.util, stdlib. Nothing else.
"""
from .adapter import (
    ExecResult,
    ExecutionAdapter,
    ExecutionRefused,
    RC_OUTPUT_LIMIT,
    RC_SPAWN_FAILED,
    RC_TIMEOUT,
)
from .containment import ContainmentUnavailable, HARDENING_ONLY, REAL_BOUNDARIES, describe, detect
from .env import build_env, is_forbidden, leaked_names

__all__ = [
    "ExecResult", "ExecutionAdapter", "ExecutionRefused",
    "RC_OUTPUT_LIMIT", "RC_SPAWN_FAILED", "RC_TIMEOUT",
    "ContainmentUnavailable", "HARDENING_ONLY", "REAL_BOUNDARIES", "describe", "detect",
    "build_env", "is_forbidden", "leaked_names",
]
