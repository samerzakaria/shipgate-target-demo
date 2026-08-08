"""Typed findings.

A finding is a defect the gate observed. Severity drives blocking; `SHOWSTOPPER` and
`CRITICAL` are non-waivable by construction — `Finding.waive()` refuses them, so there is
no code path that turns one into an accepted risk.
"""
import dataclasses
import enum
import operator as _operator
from typing import Optional, Tuple

from ..util.canonical import digest_of
from ..util.clock import utcnow_iso


class Severity(str, enum.Enum):
    SHOWSTOPPER = "SHOWSTOPPER"
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

    @property
    def rank(self):
        return _RANK[self]

    # Severity subclasses `str` so it serialises cleanly, which means Python would happily
    # fall back to LEXICOGRAPHIC comparison against a bare string — making
    # `Severity.MAJOR < "MINOR"` True even though MAJOR outranks MINOR. Every ordering
    # operator therefore raises on a non-Severity rather than returning NotImplemented.
    def _cmp(self, other, op):
        if not isinstance(other, Severity):
            raise TypeError(
                f"refusing to order Severity against {type(other).__name__}: string "
                "comparison would silently use alphabetical order, not severity rank")
        return op(self.rank, other.rank)

    def __lt__(self, other):
        return self._cmp(other, _operator.lt)

    def __le__(self, other):
        return self._cmp(other, _operator.le)

    def __gt__(self, other):
        return self._cmp(other, _operator.gt)

    def __ge__(self, other):
        return self._cmp(other, _operator.ge)


_RANK = {
    Severity.INFO: 0,
    Severity.MINOR: 1,
    Severity.MAJOR: 2,
    Severity.CRITICAL: 3,
    Severity.SHOWSTOPPER: 4,
}

#: Severities that block a PASS while OPEN. Waiving them is refused, not merely discouraged.
BLOCKING = frozenset({Severity.SHOWSTOPPER, Severity.CRITICAL, Severity.MAJOR})
NON_WAIVABLE = frozenset({Severity.SHOWSTOPPER, Severity.CRITICAL})


class FindingState(str, enum.Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    #: Recorded, reasoned, human-named acceptance. Never available for NON_WAIVABLE.
    WAIVED = "WAIVED"
    #: Could not be determined. Requires a recorded reason; without one it stays blocking.
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclasses.dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    state: FindingState
    title: str
    detail: str
    #: The layer/collector that raised it, e.g. "runtime_probe", "mutation", "a11y".
    source: str
    #: Machine reason code from models.reasons, when the finding maps to one.
    reason_code: Optional[str] = None
    location: Optional[str] = None
    evidence_refs: Tuple[str, ...] = ()
    #: Populated only for WAIVED / UNVERIFIABLE. A reasonless downgrade stays blocking.
    reason: Optional[str] = None
    #: Named human accountable for a waiver. Required for WAIVED.
    authority: Optional[str] = None
    recorded_at: str = dataclasses.field(default_factory=utcnow_iso)
    #: True for a Critical User Journey defect: non-mockable, non-waivable, non-downgradable.
    cuj: bool = False

    def __post_init__(self):
        if self.state is FindingState.WAIVED:
            if self.severity in NON_WAIVABLE:
                raise ValueError(
                    f"finding {self.id}: severity {self.severity.value} is non-waivable")
            if self.cuj:
                raise ValueError(f"finding {self.id}: a CUJ finding is non-waivable")
            if not (self.reason and self.authority):
                raise ValueError(
                    f"finding {self.id}: a waiver needs both a reason and a named authority")

    @property
    def blocks(self):
        """True while this finding prevents a PASS.

        OPEN blocking severities block. UNVERIFIABLE blocks unless a reason was recorded —
        and always blocks for a CUJ, which cannot be downgraded at all.
        """
        if self.state is FindingState.FIXED:
            return False
        if self.state is FindingState.WAIVED:
            return False
        if self.state is FindingState.UNVERIFIABLE:
            if self.cuj:
                return True
            if not self.reason:
                return True
            return self.severity in NON_WAIVABLE
        return self.severity in BLOCKING or self.cuj

    def waive(self, reason, authority):
        """Return a WAIVED copy, or raise for a non-waivable finding."""
        if self.severity in NON_WAIVABLE or self.cuj:
            raise ValueError(
                f"finding {self.id}: refusing to waive {self.severity.value}"
                f"{' CUJ' if self.cuj else ''}")
        return dataclasses.replace(self, state=FindingState.WAIVED,
                                   reason=reason, authority=authority)

    def digest(self):
        return digest_of(self.to_json())

    def to_json(self):
        return {
            "id": self.id,
            "severity": self.severity.value,
            "state": self.state.value,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "reasonCode": self.reason_code,
            "location": self.location,
            "evidenceRefs": list(self.evidence_refs),
            "reason": self.reason,
            "authority": self.authority,
            "recordedAt": self.recorded_at,
            "cuj": self.cuj,
            "blocks": self.blocks,
        }


def blocking_findings(findings):
    return [f for f in findings if f.blocks]


def summarise(findings):
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {
        "total": len(findings),
        "bySeverity": counts,
        "blocking": len(blocking_findings(findings)),
    }
