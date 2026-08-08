"""Typed evidence.

Every collector returns Evidence. Evidence is *what was observed*, never *what it means*
— it carries no verdict. The semantic engine is the only thing that turns evidence into a
status, which is what keeps a collector from being able to pass the gate by itself.

Fail-closed is structural here: `EvidenceStatus` has no "assumed OK" member. A collector
that could not run produces ERROR or ABSENT, and the engine treats both as failing when
the evidence is required.
"""
import dataclasses
import enum
from typing import Any, Dict, Optional, Tuple

from ..util.canonical import digest_of
from ..util.clock import age_seconds, utcnow_iso
from ..version import EVIDENCE_SCHEMA_VERSION


class EvidenceStatus(str, enum.Enum):
    #: Collector ran and produced a usable observation.
    COLLECTED = "COLLECTED"
    #: Collector ran but the observation is partial — some subjects were not covered.
    PARTIAL = "PARTIAL"
    #: Collector could not run (tool missing, containment refused, target unbootable).
    ERROR = "ERROR"
    #: Collector was not applicable / not requested for this profile.
    ABSENT = "ABSENT"


class EvidenceKind(str, enum.Enum):
    STACK = "STACK"
    LEDGER = "LEDGER"
    RUNTIME_PROBE = "RUNTIME_PROBE"
    UI_CRAWL = "UI_CRAWL"
    ACCESSIBILITY = "ACCESSIBILITY"
    PERFORMANCE = "PERFORMANCE"
    SECURITY = "SECURITY"
    #: The mechanical floor of Phase A2: a requirements manifest whose every entry has a
    #: source span and a link that resolves, over documents that were all actually cited.
    REQUIREMENTS = "REQUIREMENTS"
    #: The mechanical floor of Phase G2: design tokens diffed against the rendered UI.
    DESIGN_CONFORMANCE = "DESIGN_CONFORMANCE"
    #: The mechanical floor of Phase G3: one action, one label; one product, one date format.
    CROSS_SURFACE = "CROSS_SURFACE"
    #: The mechanised core of the adversarial round: the ID-coercion differential and the
    #: malformed-input property. COLLECTED evidence, admitted only after catching a seeded
    #: instance of each bug class — see collectors/adversarial.py.
    ADVERSARIAL_PROBE = "ADVERSARIAL_PROBE"
    MUTATION = "MUTATION"
    FAULT_AUDIT = "FAULT_AUDIT"
    FAIL_FIRST = "FAIL_FIRST"
    HELDOUT = "HELDOUT"
    TEST_SEAL = "TEST_SEAL"
    SPEC_SEAL = "SPEC_SEAL"
    CUJ = "CUJ"
    ENV_FAULT = "ENV_FAULT"
    WORKSPACE = "WORKSPACE"
    CONTAINMENT = "CONTAINMENT"
    FINDINGS = "FINDINGS"


@dataclasses.dataclass(frozen=True)
class EvidenceBinding:
    """What this observation is bound to. A mismatch against the run context fails closed.

    `artifact_digest` is the identity of the *thing being released* (the built artifact or,
    when there is no single artifact, the source tree digest) — it is what makes evidence
    non-transferable between builds.
    """
    run_id: str
    round_index: int
    repository: str
    commit: str
    tree_digest: str
    artifact_id: Optional[str] = None
    artifact_digest: Optional[str] = None

    def to_json(self):
        return {
            "runId": self.run_id,
            "round": self.round_index,
            "repository": self.repository,
            "commit": self.commit,
            "treeDigest": self.tree_digest,
            "artifactId": self.artifact_id,
            "artifactDigest": self.artifact_digest,
        }


@dataclasses.dataclass(frozen=True)
class Evidence:
    """One collector observation, bound to a run.

    `payload` must be canonicalisable (see util.canonical) — a collector cannot smuggle an
    opaque object past the digest.
    """
    kind: EvidenceKind
    collector: str
    collector_version: str
    status: EvidenceStatus
    binding: EvidenceBinding
    collected_at: str
    payload: Dict[str, Any] = dataclasses.field(default_factory=dict)
    #: Human-facing note. NEVER consulted by the engine — text is not evidence.
    note: str = ""
    #: Subjects the collector was asked to cover but could not. Non-empty => PARTIAL at best.
    uncovered: Tuple[str, ...] = ()
    schema: str = EVIDENCE_SCHEMA_VERSION

    # --- construction helpers --------------------------------------------------------
    @staticmethod
    def collected(kind, collector, version, binding, payload, note="", uncovered=()):
        status = EvidenceStatus.PARTIAL if uncovered else EvidenceStatus.COLLECTED
        return Evidence(kind=kind, collector=collector, collector_version=version,
                        status=status, binding=binding, collected_at=utcnow_iso(),
                        payload=payload, note=note, uncovered=tuple(uncovered))

    @staticmethod
    def error(kind, collector, version, binding, note, payload=None):
        return Evidence(kind=kind, collector=collector, collector_version=version,
                        status=EvidenceStatus.ERROR, binding=binding,
                        collected_at=utcnow_iso(), payload=payload or {}, note=note)

    @staticmethod
    def absent(kind, collector, version, binding, note=""):
        return Evidence(kind=kind, collector=collector, collector_version=version,
                        status=EvidenceStatus.ABSENT, binding=binding,
                        collected_at=utcnow_iso(), payload={}, note=note)

    # --- properties -------------------------------------------------------------------
    @property
    def usable(self):
        """True only for a complete observation. PARTIAL is deliberately NOT usable on its
        own — the engine decides whether partial coverage satisfies a specific check."""
        return self.status is EvidenceStatus.COLLECTED

    def digest(self):
        return digest_of(self.to_json())

    def is_stale(self, max_age_seconds):
        """None => unparseable timestamp; the caller must fail closed on None."""
        age = age_seconds(self.collected_at)
        if age is None:
            return None
        if age < 0:
            return True  # forward-dated evidence is not fresh, it is wrong
        return age > max_age_seconds

    def to_json(self):
        return {
            "schema": self.schema,
            "kind": self.kind.value,
            "collector": self.collector,
            "collectorVersion": self.collector_version,
            "status": self.status.value,
            "binding": self.binding.to_json(),
            "collectedAt": self.collected_at,
            "payload": self.payload,
            "uncovered": list(self.uncovered),
            "note": self.note,
        }


class EvidenceSet:
    """The collected evidence for one run, addressed by kind.

    Two collectors of the same kind that disagree is a CONTRADICTION, not a merge: the set
    records both and `contradictions()` surfaces them so the engine can fail closed.
    """

    def __init__(self, items=()):
        self._items = list(items)

    def add(self, ev):
        if not isinstance(ev, Evidence):
            raise TypeError(f"EvidenceSet accepts Evidence, got {type(ev).__name__}")
        self._items.append(ev)
        return self

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

    def of_kind(self, kind):
        return [e for e in self._items if e.kind is kind]

    def first(self, kind):
        got = self.of_kind(kind)
        return got[0] if got else None

    def kinds(self):
        return {e.kind for e in self._items}

    def contradictions(self):
        """Kinds carrying more than one COLLECTED observation with differing payload digests."""
        out = []
        by_kind = {}
        for e in self._items:
            if e.status in (EvidenceStatus.COLLECTED, EvidenceStatus.PARTIAL):
                by_kind.setdefault(e.kind, []).append(e)
        for kind, evs in sorted(by_kind.items(), key=lambda kv: kv[0].value):
            digests = {digest_of(e.payload) for e in evs}
            if len(digests) > 1:
                out.append({
                    "kind": kind.value,
                    "collectors": sorted({e.collector for e in evs}),
                    "payloadDigests": sorted(digests),
                })
        return out

    def binding_mismatches(self, expected):
        """Evidence whose binding disagrees with the run's expected binding."""
        out = []
        want = expected.to_json()
        for e in self._items:
            got = e.binding.to_json()
            diff = {k: [want.get(k), got.get(k)]
                    for k in ("runId", "repository", "commit", "artifactDigest")
                    if want.get(k) is not None and want.get(k) != got.get(k)}
            if diff:
                out.append({"kind": e.kind.value, "collector": e.collector, "diff": diff})
        return out

    def input_digests(self):
        """Stable per-kind input digest list that goes into the decision."""
        rows = []
        for e in sorted(self._items, key=lambda x: (x.kind.value, x.collector)):
            rows.append({
                "kind": e.kind.value,
                "collector": e.collector,
                "collectorVersion": e.collector_version,
                "status": e.status.value,
                "digest": e.digest(),
            })
        return rows

    def to_json(self):
        return [e.to_json() for e in self._items]
