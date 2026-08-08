"""Runtime policy — HOW the gate is operated, as distinct from WHAT it requires (Profile).

Policy holds enforcement mode, containment requirements, caching, break-glass, and a
*reference* to authority configuration. It deliberately contains no authority code and no
authority types: the semantic core reads `authority_requested` as a bare bool and never
learns what an attestation is.
"""
import dataclasses
import enum
import os
from typing import Optional, Tuple

from ..util.canonical import digest_of


class Mode(str, enum.Enum):
    #: Report only; a FAILED decision does not block the caller (exit 0 by convention of
    #: the caller, not of the decision — the decision itself is unchanged).
    ADVISORY = "advisory"
    #: Report and record for metrics; still non-blocking. Used while adopting enforcement.
    OBSERVE = "observe"
    #: Blocking. The default.
    ENFORCE = "enforce"


@dataclasses.dataclass(frozen=True)
class BreakGlass:
    """An audited emergency override.

    Break-glass never changes the semantic status and never yields VERIFIED. It records
    that a human overrode a FAILED gate, with a name and a reason, so the override is
    visible in the decision instead of being laundered into a pass.
    """
    active: bool
    authority: str = ""
    reason: str = ""
    ticket: str = ""

    def __post_init__(self):
        if self.active and not (self.authority and self.reason):
            raise ValueError("break-glass requires a named authority and a reason")

    def to_json(self):
        return {"active": self.active, "authority": self.authority,
                "reason": self.reason, "ticket": self.ticket}


@dataclasses.dataclass(frozen=True)
class ContainmentPolicy:
    """What counts as a real boundary for target-controlled processes.

    `required=True` with nothing available is a FAIL-CLOSED condition. There is no
    unrestricted fallback: `allow_host_exec` is a separate, explicit, audited consent that
    the caller must set, and even then the run records containment as NOT_ESTABLISHED so it
    can never be presented as contained.
    """
    required: bool = True
    accepted: Tuple[str, ...] = ("container", "bwrap")
    #: Explicit operator consent to run target code on the host with NO boundary.
    allow_host_exec: bool = False
    default_timeout_seconds: int = 600
    max_output_bytes: int = 8 * 1024 * 1024

    def to_json(self):
        return {"required": self.required, "accepted": list(self.accepted),
                "allowHostExec": self.allow_host_exec,
                "defaultTimeoutSeconds": self.default_timeout_seconds,
                "maxOutputBytes": self.max_output_bytes}


@dataclasses.dataclass(frozen=True)
class CachePolicy:
    """Safe caching: results are keyed by input digest, so a cache hit is only ever reused
    for byte-identical inputs. Never cache a decision itself — only collector evidence."""
    enabled: bool = False
    directory: Optional[str] = None
    max_age_seconds: int = 3600

    def to_json(self):
        return {"enabled": self.enabled, "directory": self.directory,
                "maxAgeSeconds": self.max_age_seconds}


@dataclasses.dataclass(frozen=True)
class Policy:
    mode: Mode = Mode.ENFORCE
    containment: ContainmentPolicy = dataclasses.field(default_factory=ContainmentPolicy)
    cache: CachePolicy = dataclasses.field(default_factory=CachePolicy)
    break_glass: BreakGlass = dataclasses.field(default_factory=lambda: BreakGlass(False))
    #: Whether the caller ASKED for external authority. The semantic core only reads this
    #: to decide whether an absent kit should be reported as UNAVAILABLE vs NONE.
    authority_requested: bool = False
    #: Opaque path handed to the authority kit, if present. Never opened by the core.
    authority_config_path: Optional[str] = None
    parallelism: int = 1

    def digest(self):
        return digest_of(self.to_json())

    def to_json(self):
        return {
            "mode": self.mode.value,
            "containment": self.containment.to_json(),
            "cache": self.cache.to_json(),
            "breakGlass": self.break_glass.to_json(),
            "authorityRequested": self.authority_requested,
            "authorityConfigPath": self.authority_config_path,
            "parallelism": self.parallelism,
        }

    @staticmethod
    def from_env(env=None):
        """Build a policy from the environment. Defaults are the STRICT ones.

        Only `SHIPGATE_ALLOW_HOST_EXEC=1` can relax containment, and it is recorded in the
        decision, so relaxing it is visible rather than silent.
        """
        e = os.environ if env is None else env
        mode_raw = (e.get("SHIPGATE_MODE") or "enforce").strip().lower()
        mode = Mode(mode_raw) if mode_raw in {m.value for m in Mode} else Mode.ENFORCE
        bg_active = (e.get("SHIPGATE_BREAK_GLASS") or "").strip() == "1"
        return Policy(
            mode=mode,
            containment=ContainmentPolicy(
                required=(e.get("SHIPGATE_CONTAINMENT_REQUIRED", "1").strip() != "0"),
                allow_host_exec=(e.get("SHIPGATE_ALLOW_HOST_EXEC", "").strip() == "1"),
            ),
            cache=CachePolicy(
                enabled=(e.get("SHIPGATE_CACHE", "").strip() == "1"),
                directory=e.get("SHIPGATE_CACHE_DIR") or None,
            ),
            break_glass=BreakGlass(
                active=bg_active,
                authority=(e.get("SHIPGATE_BREAK_GLASS_AUTHORITY") or "") if bg_active else "",
                reason=(e.get("SHIPGATE_BREAK_GLASS_REASON") or "") if bg_active else "",
                ticket=e.get("SHIPGATE_BREAK_GLASS_TICKET") or "",
            ),
            authority_requested=(e.get("SHIPGATE_AUTHORITY", "").strip() == "1"),
            authority_config_path=e.get("SHIPGATE_AUTHORITY_CONFIG") or None,
            parallelism=max(1, int(e.get("SHIPGATE_PARALLELISM") or "1")),
        )
