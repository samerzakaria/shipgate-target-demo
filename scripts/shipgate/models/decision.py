"""The immutable decision — the product contract.

Two independent axes, represented separately and never collapsed into one field:

    Axis B (semantics)  -> SemanticStatus   PASSED | FAILED
    Axis A (provenance) -> ProvenanceStatus NONE | UNAVAILABLE | CI_ATTESTED | INDEPENDENTLY_ATTESTED

`Outcome` is DERIVED from the pair. There is no `AUTHORITATIVE_PASS`: that legacy value
conflated "the evidence is real" with "the run passed", which is exactly the confusion this
model exists to prevent. Authentic evidence does not imply semantic success; semantic
success alone does not establish authority.

Immutability is structural, not a convention. `Decision` is a frozen dataclass, its
collections are tuples, and the only way to add provenance is `AttestedDecision`, which
*wraps* a decision and carries its digest. An authority adapter therefore cannot alter,
repair, replace, downgrade, or bypass a decision — the worst it can do is fail to attest
one, and `derive_outcome` refuses to attest a FAILED decision regardless of what an
adapter claims.
"""
import dataclasses
import enum
from typing import Any, Dict, Optional, Tuple

from ..util.canonical import canonical_bytes, digest_of
from ..util.clock import utcnow_iso
from ..version import DECISION_SCHEMA_VERSION, ENGINE_ID
from . import reasons as R
from .coverage import PhaseCoverage
from .finding import Finding


class SemanticStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class ProvenanceStatus(str, enum.Enum):
    #: No external authority was requested. This is the normal developer-loop state.
    NONE = "NONE"
    #: Authority was requested but the environment is absent, unsupported, or unqualified.
    UNAVAILABLE = "UNAVAILABLE"
    #: A configured external CI identity + attestation verifier established the evidence.
    CI_ATTESTED = "CI_ATTESTED"
    #: Additionally verified by a separate external principal / trust boundary.
    INDEPENDENTLY_ATTESTED = "INDEPENDENTLY_ATTESTED"


class Outcome(str, enum.Enum):
    VERIFIED = "VERIFIED"
    CI_ATTESTED = "CI_ATTESTED"
    INDEPENDENTLY_ATTESTED = "INDEPENDENTLY_ATTESTED"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    FAILED = "FAILED"


#: Process exit codes. Part of the consumer contract — never grep the outcome string.
EXIT_CODES = {
    Outcome.VERIFIED: 0,
    Outcome.CI_ATTESTED: 0,
    Outcome.INDEPENDENTLY_ATTESTED: 0,
    Outcome.AUTHORITY_UNAVAILABLE: 3,
    Outcome.FAILED: 1,
}


def derive_outcome(semantic, provenance):
    """The ONLY place an outcome is computed.

    A FAILED semantic status collapses every provenance value to FAILED — no adapter can
    turn a failed or incomplete semantic decision into an attested success.
    """
    if semantic is not SemanticStatus.PASSED:
        return Outcome.FAILED
    if provenance is ProvenanceStatus.INDEPENDENTLY_ATTESTED:
        return Outcome.INDEPENDENTLY_ATTESTED
    if provenance is ProvenanceStatus.CI_ATTESTED:
        return Outcome.CI_ATTESTED
    if provenance is ProvenanceStatus.UNAVAILABLE:
        return Outcome.AUTHORITY_UNAVAILABLE
    return Outcome.VERIFIED


# ---------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CheckResult:
    check_id: str
    title: str
    passed: bool
    required: bool
    showstopper: bool
    evidence_kind: str
    reason_code: Optional[str] = None
    detail: str = ""

    def to_json(self):
        return {
            "checkId": self.check_id, "title": self.title, "passed": self.passed,
            "required": self.required, "showstopper": self.showstopper,
            "evidenceKind": self.evidence_kind, "reasonCode": self.reason_code,
            "detail": self.detail,
        }


@dataclasses.dataclass(frozen=True)
class ThresholdResult:
    threshold_id: str
    metric: str
    comparison: str
    required_value: int
    measured_value: Optional[int]
    passed: bool
    required: bool
    unit: str = ""
    reason_code: Optional[str] = None

    def to_json(self):
        return {
            "thresholdId": self.threshold_id, "metric": self.metric,
            "comparison": self.comparison, "requiredValue": self.required_value,
            "measuredValue": self.measured_value, "passed": self.passed,
            "required": self.required, "unit": self.unit, "reasonCode": self.reason_code,
        }


@dataclasses.dataclass(frozen=True)
class CujOutcome:
    id: str
    title: str
    status: str          # EVIDENCED | NOT_EVIDENCED | ERROR
    evidence_ref: Optional[str] = None
    detail: str = ""

    @property
    def evidenced(self):
        return self.status == "EVIDENCED"

    def to_json(self):
        return {"id": self.id, "title": self.title, "status": self.status,
                "evidenceRef": self.evidence_ref, "detail": self.detail}


@dataclasses.dataclass(frozen=True)
class HeldOutOutcome:
    """A held-out suite result that is BOUND *and* EVALUATED.

    v3.8 bound held-out results to the run and then never read the pass/fail. Both fields
    are mandatory here, and `evaluated=False` is a semantic failure, not a note.
    """
    suite_id: str
    bound: bool
    evaluated: bool
    total: int
    passed: int
    failed: int
    errored: int
    binding_digest: Optional[str] = None
    detail: str = ""

    @property
    def green(self):
        return (self.bound and self.evaluated and self.total > 0
                and self.failed == 0 and self.errored == 0 and self.passed == self.total)

    def to_json(self):
        return {
            "suiteId": self.suite_id, "bound": self.bound, "evaluated": self.evaluated,
            "total": self.total, "passed": self.passed, "failed": self.failed,
            "errored": self.errored, "bindingDigest": self.binding_digest,
            "green": self.green, "detail": self.detail,
        }


@dataclasses.dataclass(frozen=True)
class SubjectIdentity:
    """WHAT was evaluated. Evidence that does not bind to this is not about this release."""
    repository: str
    commit: str
    tree_digest: str
    artifact_id: Optional[str] = None
    artifact_digest: Optional[str] = None
    branch: Optional[str] = None

    def to_json(self):
        return {
            "repository": self.repository, "commit": self.commit,
            "treeDigest": self.tree_digest, "artifactId": self.artifact_id,
            "artifactDigest": self.artifact_digest, "branch": self.branch,
        }


@dataclasses.dataclass(frozen=True)
class Decision:
    """A deterministic, canonical, versioned semantic decision. Frozen and self-describing.

    The digest covers everything except itself, so two runs of the same engine over the same
    inputs produce the same digest — which is what makes "authority removal leaves the
    semantic decision identical" a testable claim rather than an assertion.
    """
    decision_id: str
    created_at: str
    subject: SubjectIdentity
    profile_id: str
    profile_digest: str
    semantic_status: SemanticStatus
    reason_codes: Tuple[str, ...]
    checks: Tuple[CheckResult, ...]
    thresholds: Tuple[ThresholdResult, ...]
    cujs: Tuple[CujOutcome, ...]
    heldout: Tuple[HeldOutOutcome, ...]
    findings: Tuple[Finding, ...]
    required_evidence: Tuple[str, ...]
    received_evidence: Tuple[Dict[str, Any], ...]
    input_digests: Tuple[Dict[str, Any], ...]
    containment: Dict[str, Any]
    #: SELF-ATTESTED phase coverage. Sits beside the evidence, never inside it, and may only
    #: ever SUBTRACT from how the outcome reads — see `models.coverage`. It is part of the
    #: digest because it is part of what was decided; it is not part of `checks`,
    #: `thresholds` or `receivedEvidence` because it is not evidence.
    coverage: Optional[PhaseCoverage] = None
    #: Recorded, audited emergency override. A break-glass run is NEVER reported as VERIFIED.
    break_glass: Optional[Dict[str, Any]] = None
    mode: str = "enforce"          # advisory | observe | enforce
    engine: str = ENGINE_ID
    schema: str = DECISION_SCHEMA_VERSION
    residual_risk: str = ""

    # --- derived ---------------------------------------------------------------------
    @property
    def provenance_status(self):
        """A bare decision claims NO provenance authority. Ever."""
        return ProvenanceStatus.NONE

    @property
    def outcome(self):
        return derive_outcome(self.semantic_status, ProvenanceStatus.NONE)

    @property
    def exit_code(self):
        return EXIT_CODES[self.outcome]

    @property
    def coverage_suffix(self):
        """The qualification appended to the outcome when it is DISPLAYED. Never a status.

        `outcome` and `exit_code` above are deliberately untouched by coverage: a caveat
        says something was not collected, which is not the same as something having failed,
        and a consumer that branches on the outcome must not start branching on this.
        """
        return self.coverage.display_suffix() if self.coverage else ""

    def display_outcome(self):
        suffix = self.coverage_suffix
        return f"{self.outcome.value} — {suffix}" if suffix else self.outcome.value

    def digest(self):
        return digest_of(self.to_json())

    def canonical(self):
        return canonical_bytes(self.to_json())

    # --- serialisation ----------------------------------------------------------------
    def to_json(self):
        return {
            "schema": self.schema,
            "engine": self.engine,
            "decisionId": self.decision_id,
            "createdAt": self.created_at,
            "mode": self.mode,
            "subject": self.subject.to_json(),
            "profile": {"id": self.profile_id, "digest": self.profile_digest},
            "semanticStatus": self.semantic_status.value,
            "provenanceStatus": ProvenanceStatus.NONE.value,
            "outcome": self.outcome.value,
            "reasonCodes": list(self.reason_codes),
            "checks": [c.to_json() for c in self.checks],
            "thresholds": [t.to_json() for t in self.thresholds],
            "cujs": [c.to_json() for c in self.cujs],
            "heldOut": [h.to_json() for h in self.heldout],
            "findings": [f.to_json() for f in self.findings],
            "requiredEvidence": list(self.required_evidence),
            "receivedEvidence": [dict(e) for e in self.received_evidence],
            "inputDigests": [dict(d) for d in self.input_digests],
            "containment": dict(self.containment),
            "coverage": self.coverage.to_json() if self.coverage else None,
            "displayOutcome": self.display_outcome(),
            "breakGlass": self.break_glass,
            "residualRisk": self.residual_risk,
        }

    def to_envelope(self):
        """The on-disk artifact: the decision plus its own digest."""
        body = self.to_json()
        return {"decision": body, "decisionDigest": digest_of(body)}


# ---------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Attestation:
    """What an authority adapter produced ABOUT a decision. It never contains the decision.

    `decision_digest` is the only link; if it does not match the decision it is presented
    with, `AttestedDecision` refuses to exist.
    """
    provenance_status: ProvenanceStatus
    decision_digest: str
    verifier: str
    verifier_version: str
    reason_codes: Tuple[str, ...]
    identity: Optional[Dict[str, Any]] = None
    binding: Optional[Dict[str, Any]] = None
    freshness: Optional[Dict[str, Any]] = None
    principals: Tuple[Dict[str, Any], ...] = ()
    created_at: str = dataclasses.field(default_factory=utcnow_iso)
    detail: str = ""

    def __post_init__(self):
        bad = [c for c in self.reason_codes if c not in R.AUTHORITY_EMITTABLE]
        if bad:
            raise ValueError(
                f"authority adapter emitted non-authority reason codes: {bad}. "
                "An adapter may not author a semantic reason.")

    def to_json(self):
        return {
            "provenanceStatus": self.provenance_status.value,
            "decisionDigest": self.decision_digest,
            "verifier": self.verifier,
            "verifierVersion": self.verifier_version,
            "reasonCodes": list(self.reason_codes),
            "identity": self.identity,
            "binding": self.binding,
            "freshness": self.freshness,
            "principals": [dict(p) for p in self.principals],
            "createdAt": self.created_at,
            "detail": self.detail,
        }


@dataclasses.dataclass(frozen=True)
class AttestedDecision:
    """A decision PLUS an attestation about it. The decision inside is byte-identical to the
    one the semantic engine produced — this type only ever adds."""
    decision: Decision
    attestation: Attestation

    def __post_init__(self):
        got = self.decision.digest()
        if got != self.attestation.decision_digest:
            raise ValueError(
                "attestation does not bind to this decision "
                f"(decision={got[:16]}… attestation={self.attestation.decision_digest[:16]}…)")
        if (self.decision.semantic_status is not SemanticStatus.PASSED
                and self.attestation.provenance_status in (
                    ProvenanceStatus.CI_ATTESTED, ProvenanceStatus.INDEPENDENTLY_ATTESTED)):
            raise ValueError(
                "refusing to attest a decision whose semantic status is "
                f"{self.decision.semantic_status.value}")

    @property
    def semantic_status(self):
        return self.decision.semantic_status

    @property
    def provenance_status(self):
        return self.attestation.provenance_status

    @property
    def outcome(self):
        return derive_outcome(self.semantic_status, self.provenance_status)

    @property
    def exit_code(self):
        return EXIT_CODES[self.outcome]

    def display_outcome(self):
        """The attested outcome, carrying the same coverage qualification as the bare one.

        An attestation says who vouches for the evidence. It says nothing about which
        phases of the procedure were performed, so it cannot clear a coverage caveat —
        adding authority to a run with Phase H unrun does not make Phase H run.
        """
        suffix = self.decision.coverage_suffix
        return f"{self.outcome.value} — {suffix}" if suffix else self.outcome.value

    def to_json(self):
        body = self.decision.to_json()
        return {
            "decision": body,
            "decisionDigest": self.decision.digest(),
            "attestation": self.attestation.to_json(),
            "provenanceStatus": self.provenance_status.value,
            "outcome": self.outcome.value,
            "displayOutcome": self.display_outcome(),
        }
