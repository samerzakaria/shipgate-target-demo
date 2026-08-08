"""Semantic profiles — WHAT the gate requires, expressed as data.

A profile is deterministic and digestible. The decision carries the profile's id AND its
digest, so a consumer can tell whether two decisions were judged by the same rules, and a
profile edited between runs cannot masquerade as the one that was actually applied.

Two profiles ship: `standard` (the default) and `deep`. Escalation from standard to deep is
by explicit signal — declared risk, a change inside a protected area, unresolved
uncertainty, or policy — never "maximum ceremony, always". An LLM may RECOMMEND escalation;
`Profile.escalate` only ever moves up the ladder, so a recommendation can never lower a
deterministic requirement.
"""
import dataclasses
import enum
from typing import Dict, Optional, Tuple

from ..util.canonical import digest_of
from ..version import PROFILE_SCHEMA_VERSION
from .evidence import EvidenceKind


class Comparison(str, enum.Enum):
    AT_LEAST = "AT_LEAST"
    AT_MOST = "AT_MOST"
    EQUALS = "EQUALS"


@dataclasses.dataclass(frozen=True)
class Threshold:
    """A numeric bar. `value` is an int (or an int-scaled percentage) — never a float, so
    the profile digest is stable across platforms."""
    id: str
    metric: str
    comparison: Comparison
    value: int
    evidence_kind: EvidenceKind
    #: When True, an UNMEASURED metric fails. When False, unmeasured is recorded and skipped.
    required: bool = True
    unit: str = ""
    description: str = ""
    #: Applicability condition, resolved against detected-stack evidence at evaluation time.
    #: One of the keys in semantic.checks.CONDITIONS. A threshold that does not apply is
    #: recorded as NOT_APPLICABLE and never silently treated as passing.
    applies_when: str = "always"

    def satisfied_by(self, measured):
        """(ok, reason_code_or_None). `measured=None` means unmeasured."""
        from . import reasons
        if measured is None:
            if self.required:
                return False, reasons.SEM_THRESHOLD_UNMEASURED
            return True, None
        if self.comparison is Comparison.AT_LEAST:
            ok = measured >= self.value
        elif self.comparison is Comparison.AT_MOST:
            ok = measured <= self.value
        else:
            ok = measured == self.value
        return (True, None) if ok else (False, reasons.SEM_THRESHOLD_NOT_MET)

    def to_json(self):
        return {
            "id": self.id, "metric": self.metric, "comparison": self.comparison.value,
            "value": self.value, "evidenceKind": self.evidence_kind.value,
            "required": self.required, "unit": self.unit, "description": self.description,
            "appliesWhen": self.applies_when,
        }


@dataclasses.dataclass(frozen=True)
class CheckSpec:
    """One required semantic check.

    `evaluator` names a function registered in semantic.checks.REGISTRY. Naming rather than
    embedding keeps the profile pure data and keeps evaluation logic in one reviewable place.
    """
    id: str
    title: str
    evaluator: str
    evidence_kind: EvidenceKind
    required: bool = True
    #: A failure of this check is a SHOWSTOPPER rather than an ordinary failure.
    showstopper: bool = False
    description: str = ""
    params: Dict[str, int] = dataclasses.field(default_factory=dict)
    #: Applicability condition (see semantic.checks.CONDITIONS). When the condition cannot
    #: be evaluated — e.g. stack detection failed — the check is treated as APPLICABLE, so
    #: an unknown stack can never skip a required check.
    applies_when: str = "always"

    def to_json(self):
        return {
            "id": self.id, "title": self.title, "evaluator": self.evaluator,
            "evidenceKind": self.evidence_kind.value, "required": self.required,
            "showstopper": self.showstopper, "description": self.description,
            "params": dict(sorted(self.params.items())),
            "appliesWhen": self.applies_when,
        }


@dataclasses.dataclass(frozen=True)
class ConditionalEvidence:
    """Evidence required only when a condition holds (e.g. accessibility on a UI stack).

    An unresolvable condition resolves to REQUIRED — the gate never skips evidence because
    it could not work out whether it was needed.
    """
    kind: EvidenceKind
    applies_when: str

    def to_json(self):
        return {"kind": self.kind.value, "appliesWhen": self.applies_when}


@dataclasses.dataclass(frozen=True)
class Profile:
    id: str
    title: str
    description: str
    checks: Tuple[CheckSpec, ...]
    thresholds: Tuple[Threshold, ...]
    required_evidence: Tuple[EvidenceKind, ...]
    conditional_evidence: Tuple[ConditionalEvidence, ...] = ()
    #: Evidence older than this (seconds) is STALE and fails closed when required.
    max_evidence_age_seconds: int = 86400
    #: Consecutive clean rounds needed before the gate may pass.
    required_clean_rounds: int = 2
    #: Containment kinds accepted as a real boundary for target-controlled processes.
    accepted_containment: Tuple[str, ...] = ("container", "bwrap")
    #: When True, a run with no accepted containment cannot pass at all.
    containment_required: bool = True
    rank: int = 0
    schema: str = PROFILE_SCHEMA_VERSION

    def digest(self):
        return digest_of(self.to_json())

    def check(self, check_id):
        for c in self.checks:
            if c.id == check_id:
                return c
        return None

    def escalate(self, other):
        """Return whichever profile is stricter. Escalation is one-way by rank."""
        return other if other.rank > self.rank else self

    def to_json(self):
        return {
            "schema": self.schema,
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "rank": self.rank,
            "checks": [c.to_json() for c in self.checks],
            "thresholds": [t.to_json() for t in self.thresholds],
            "requiredEvidence": [k.value for k in self.required_evidence],
            "conditionalEvidence": [c.to_json() for c in self.conditional_evidence],
            "maxEvidenceAgeSeconds": self.max_evidence_age_seconds,
            "requiredCleanRounds": self.required_clean_rounds,
            "acceptedContainment": list(self.accepted_containment),
            "containmentRequired": self.containment_required,
        }


# ---------------------------------------------------------------------------------------
# Escalation signals
# ---------------------------------------------------------------------------------------

class EscalationSignal(str, enum.Enum):
    DECLARED_RISK = "DECLARED_RISK"
    PROTECTED_AREA_CHANGED = "PROTECTED_AREA_CHANGED"
    UNRESOLVED_UNCERTAINTY = "UNRESOLVED_UNCERTAINTY"
    POLICY = "POLICY"


_SIGNAL_REASON = {
    EscalationSignal.DECLARED_RISK: "PRF_ESCALATED_RISK",
    EscalationSignal.PROTECTED_AREA_CHANGED: "PRF_ESCALATED_PROTECTED_AREA",
    EscalationSignal.UNRESOLVED_UNCERTAINTY: "PRF_ESCALATED_UNCERTAINTY",
    EscalationSignal.POLICY: "PRF_ESCALATED_POLICY",
}


@dataclasses.dataclass(frozen=True)
class ProfileResolution:
    """The audit trail of how the effective profile was chosen."""
    requested: str
    effective: Profile
    signals: Tuple[EscalationSignal, ...] = ()
    #: Recommendations that were REFUSED because they would have lowered the bar.
    refused_downgrades: Tuple[str, ...] = ()

    def reason_codes(self):
        codes = ["PRF_RESOLVED"]
        codes += [_SIGNAL_REASON[s] for s in self.signals]
        if self.refused_downgrades:
            codes.append("PRF_DOWNGRADE_REFUSED")
        return codes

    def to_json(self):
        return {
            "requested": self.requested,
            "effectiveId": self.effective.id,
            "effectiveDigest": self.effective.digest(),
            "signals": [s.value for s in self.signals],
            "refusedDowngrades": list(self.refused_downgrades),
        }


# ---------------------------------------------------------------------------------------
# Shipped profiles
# ---------------------------------------------------------------------------------------

_CORE_CHECKS = (
    CheckSpec("wiring.no_gaps", "Every declared capability is EVIDENCED or explained",
              "ledger_no_wiring_gaps", EvidenceKind.LEDGER, showstopper=True,
              description="No ledger entry may remain UNVERIFIED or WIRING_GAP."),
    CheckSpec("runtime.served", "Declared routes are served, not merely present",
              "runtime_served", EvidenceKind.RUNTIME_PROBE, showstopper=True,
              description="Serving is judged against a per-scope 404 canary baseline, "
                          "never against response body shape."),
    CheckSpec("cuj.evidenced", "Every Critical User Journey is EVIDENCED",
              "cuj_evidenced", EvidenceKind.CUJ, showstopper=True,
              description="CUJs are non-mockable, non-waivable, non-downgradable."),
    CheckSpec("tests.fail_first", "Every admitted test provably failed on an injected fault",
              "fail_first_admitted", EvidenceKind.FAIL_FIRST,
              description="A test that kills no fault is not evidence."),
    CheckSpec("tests.seal_intact", "The test seal is intact and covers a non-empty set",
              "test_seal_intact", EvidenceKind.TEST_SEAL, showstopper=True,
              description="Covers the test command definition too, so a gutted "
                          "\"test\": \"true\" is caught."),
    CheckSpec("spec.sealed", "The specification is sealed and its drift is logged",
              "spec_sealed", EvidenceKind.SPEC_SEAL),
    CheckSpec("heldout.evaluated", "The held-out suite ran AND its outcomes were evaluated",
              "heldout_evaluated", EvidenceKind.HELDOUT, showstopper=True,
              description="Binding a held-out result is not evaluating it."),
    CheckSpec("faults.none_undetected", "The targeted fault audit found no undetected fault",
              "no_undetected_faults", EvidenceKind.FAULT_AUDIT),
    CheckSpec("security.no_serious", "No serious security finding is open",
              "security_clean", EvidenceKind.SECURITY),
    CheckSpec("adversarial.no_bypass",
              "The mechanised adversarial probe found no authorisation bypass or crash",
              "adversarial_clean", EvidenceKind.ADVERSARIAL_PROBE, showstopper=True,
              applies_when="adversarial_configured",
              description="The falsifiable core of Phase H: an ID-coercion differential "
                          "(a request as one identity must never return another's data) and "
                          "a malformed-input property (a hostile body must be refused, not "
                          "crash). Admitted only after catching a seeded instance of each "
                          "bug class. Applies once identities or write endpoints are "
                          "declared; an unconfigured run does not pass this check, it "
                          "carries a Phase H coverage caveat instead. `deep` requires the "
                          "evidence outright."),
    CheckSpec("a11y.no_serious", "No serious accessibility violation is open",
              "a11y_clean", EvidenceKind.ACCESSIBILITY, applies_when="ui",
              description="Applies to stacks that serve a user interface."),
    CheckSpec("requirements.linked",
              "Every requirement cites a source span and links to evidence that exists",
              "requirements_linked", EvidenceKind.REQUIREMENTS,
              applies_when="requirements_configured",
              description="The mechanical floor of Phase A2: ids, stated conditions, "
                          "comparable risk ranks, source spans, links that RESOLVE to a "
                          "declared CUJ / probed route / ledger capability, and no "
                          "requirements document in the tree that nothing cites. Whether "
                          "they are the RIGHT requirements stays judgement."),
    CheckSpec("design.conformant",
              "The rendered UI uses the declared design tokens",
              "design_conformant", EvidenceKind.DESIGN_CONFORMANCE,
              applies_when="design_tokens_configured",
              description="The mechanical floor of Phase G2: palette, spacing scale, type "
                          "scale, font families and radii diffed against what the pages "
                          "actually rendered with. Whether it looks good stays judgement."),
    CheckSpec("surfaces.consistent",
              "Surfaces agree with each other on labels, dates, money and numbers",
              "cross_surface_consistent", EvidenceKind.CROSS_SURFACE,
              applies_when="surfaces_comparable",
              description="The mechanical floor of Phase G3: one action one label, one "
                          "product one date format. Whether a difference MATTERS stays "
                          "judgement, so every finding names both surfaces."),
    CheckSpec("containment.enforced", "All target processes ran through the execution adapter",
              "containment_enforced", EvidenceKind.CONTAINMENT, showstopper=True),
    CheckSpec("findings.none_blocking", "No blocking finding remains open",
              "no_blocking_findings", EvidenceKind.FINDINGS, showstopper=True),
)

_DEEP_EXTRA_CHECKS = (
    CheckSpec("envfault.detected", "Environment/config faults are detected by the suite",
              "envfault_detected", EvidenceKind.ENV_FAULT,
              description="A gate that cannot notice a broken DATABASE_URL cannot notice a "
                          "dead login."),
    CheckSpec("perf.within_budget", "Measured performance is inside the declared budget",
              "perf_within_budget", EvidenceKind.PERFORMANCE, applies_when="ui"),
)

_STANDARD_THRESHOLDS = (
    Threshold("mutation.score", "mutation_score_pct", Comparison.AT_LEAST, 60,
              EvidenceKind.MUTATION, unit="%",
              description="Whole-repo mutation score."),
    Threshold("faults.undetected", "undetected_faults", Comparison.AT_MOST, 0,
              EvidenceKind.FAULT_AUDIT, unit="count"),
    Threshold("a11y.serious", "serious_violations", Comparison.AT_MOST, 0,
              EvidenceKind.ACCESSIBILITY, unit="count", applies_when="ui"),
    Threshold("security.high", "high_severity_findings", Comparison.AT_MOST, 0,
              EvidenceKind.SECURITY, unit="count"),
)

_DEEP_THRESHOLDS = _STANDARD_THRESHOLDS[1:] + (
    Threshold("mutation.score", "mutation_score_pct", Comparison.AT_LEAST, 75,
              EvidenceKind.MUTATION, unit="%",
              description="Whole-repo mutation score (deep profile)."),
    Threshold("perf.lcp_ms", "lcp_ms", Comparison.AT_MOST, 2500,
              EvidenceKind.PERFORMANCE, required=False, unit="ms", applies_when="ui"),
    Threshold("envfault.undetected", "undetected_env_faults", Comparison.AT_MOST, 0,
              EvidenceKind.ENV_FAULT, unit="count"),
)

STANDARD = Profile(
    id="standard",
    title="Standard semantic gate",
    description=(
        "The default. Proves wiring by runtime evidence, admits tests only after they have "
        "failed on an injected fault, evaluates a held-out suite, and blocks on any open "
        "showstopper, blocker, or unmet threshold."),
    checks=_CORE_CHECKS,
    thresholds=_STANDARD_THRESHOLDS,
    required_evidence=(
        EvidenceKind.STACK, EvidenceKind.LEDGER, EvidenceKind.RUNTIME_PROBE,
        EvidenceKind.CUJ, EvidenceKind.HELDOUT, EvidenceKind.TEST_SEAL,
        EvidenceKind.MUTATION, EvidenceKind.FAULT_AUDIT, EvidenceKind.SECURITY,
        EvidenceKind.CONTAINMENT, EvidenceKind.FINDINGS,
        EvidenceKind.FAIL_FIRST, EvidenceKind.SPEC_SEAL,
    ),
    conditional_evidence=(
        ConditionalEvidence(EvidenceKind.ACCESSIBILITY, "ui"),
    ),
    rank=10,
)

DEEP = Profile(
    id="deep",
    title="Deep semantic gate",
    description=(
        "Standard, plus environment/config fault detection, a performance budget, a higher "
        "mutation bar, and accessibility as required evidence. Selected by an explicit "
        "escalation signal — never applied universally."),
    checks=_CORE_CHECKS + _DEEP_EXTRA_CHECKS,
    thresholds=_DEEP_THRESHOLDS,
    # DEEP is reached by an explicit escalation signal, so it is the right place to make the
    # adversarial probe non-optional: an operator who has declared elevated risk and then
    # declined to name two disposable accounts has not covered Phase H, and on this profile
    # that is a failure rather than a caveat.
    required_evidence=STANDARD.required_evidence + (EvidenceKind.ENV_FAULT,
                                                    EvidenceKind.ADVERSARIAL_PROBE,
                                                    EvidenceKind.REQUIREMENTS),
    conditional_evidence=(
        ConditionalEvidence(EvidenceKind.ACCESSIBILITY, "ui"),
        ConditionalEvidence(EvidenceKind.UI_CRAWL, "ui"),
        ConditionalEvidence(EvidenceKind.PERFORMANCE, "ui"),
        # G2 and G3 are required on `deep` for UI stacks and only there: a service with no
        # user interface has no design system to conform to and no surfaces to compare.
        ConditionalEvidence(EvidenceKind.DESIGN_CONFORMANCE, "ui"),
        ConditionalEvidence(EvidenceKind.CROSS_SURFACE, "ui"),
    ),
    max_evidence_age_seconds=43200,
    required_clean_rounds=2,
    rank=20,
)

BUILTIN = {p.id: p for p in (STANDARD, DEEP)}
DEFAULT_PROFILE_ID = "standard"


def get(profile_id):
    """Look up a shipped profile. Unknown ids raise — never silently fall back to a laxer one."""
    try:
        return BUILTIN[profile_id]
    except KeyError:
        raise KeyError(
            f"unknown profile {profile_id!r}; known: {sorted(BUILTIN)}") from None


def resolve(requested=DEFAULT_PROFILE_ID, signals=(), recommendations=()):
    """Resolve the effective profile.

    `signals` escalate deterministically. `recommendations` are advisory profile ids (e.g.
    from an LLM triage step): one that is stricter escalates, one that is laxer is REFUSED
    and recorded — advice can raise the bar, never lower it.
    """
    base = get(requested)
    eff = base
    sigs = tuple(dict.fromkeys(signals))
    if sigs:
        eff = eff.escalate(DEEP)
    refused = []
    for rec in recommendations:
        try:
            cand = get(rec)
        except KeyError:
            refused.append(f"{rec} (unknown profile)")
            continue
        if cand.rank > eff.rank:
            eff = cand
        elif cand.rank < eff.rank:
            refused.append(f"{rec} (would lower rank {eff.rank} -> {cand.rank})")
    return ProfileResolution(requested=requested, effective=eff, signals=sigs,
                             refused_downgrades=tuple(refused))
