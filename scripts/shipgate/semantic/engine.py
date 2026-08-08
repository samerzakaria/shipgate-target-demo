"""The semantic engine — Axis B, and nothing else.

This module answers exactly one question: *does the evidence prove the evaluated run passed
its required checks, thresholds, CUJs, held-out tests, runtime checks and showstopper rules?*

It has no notion of identity, signing, attestation, transparency logs, promotion, or an
independent verifier, and it imports none of that code. `tests/boundary/` proves the
absence by AST scan, and `tests/integration/test_authority_removal.py` proves the behaviour
by deleting `shipgate/authority/` and re-running.
"""
import uuid

from ..models import reasons as R
from ..models.coverage import build as build_coverage
from ..models.decision import (
    CheckResult,
    CujOutcome,
    Decision,
    HeldOutOutcome,
    SemanticStatus,
    SubjectIdentity,
    ThresholdResult,
)
from ..models.evidence import EvidenceKind, EvidenceStatus
from ..models.finding import Finding, Severity, FindingState
from ..models.policy import Mode, Policy
from ..models.profile import DEFAULT_PROFILE_ID, resolve as resolve_profile
from ..util.clock import utcnow_iso
from . import evidence_gate
from .checks import EvalContext, REGISTRY, applies


class SemanticEngineError(RuntimeError):
    """A defect in the engine's own inputs (unknown evaluator, unusable profile).

    Deliberately fatal rather than a FAILED decision: a decision produced by an engine that
    could not run its own rules would be a lie about what was evaluated.
    """


def run_semantic_gate(evidence_set, findings=(), *, subject, profile_id=DEFAULT_PROFILE_ID,
                      escalation_signals=(), profile_recommendations=(), policy=None,
                      round_index=1, clean_round_streak=0, residual_risk="",
                      decision_id=None, expected_binding=None, phase_claims=None,
                      coverage_source="operating_agent", coverage_note=""):
    """Evaluate evidence against a profile and return an immutable `Decision`.

    This function performs no I/O and spawns no processes: everything it needs was already
    collected. That is what makes the decision reproducible and what makes "the same inputs
    produce the same digest" testable.
    """
    policy = policy or Policy()
    resolution = resolve_profile(profile_id, escalation_signals, profile_recommendations)
    profile = resolution.effective

    reason_codes = list(resolution.reason_codes())
    findings = list(findings)

    # --- evidence frontier (fail closed) -------------------------------------------------
    binding = expected_binding or _binding_from_subject(subject, evidence_set)
    evidence_problems = evidence_gate.validate(evidence_set, profile, binding)
    for code, detail in evidence_problems:
        reason_codes.append(code)
        findings.append(Finding(
            id=f"EVD-{len(findings) + 1:03d}", severity=Severity.SHOWSTOPPER,
            state=FindingState.OPEN, title="Required evidence failed validation",
            detail=detail, source="evidence_gate", reason_code=code))

    # FIX-REASON-CODE-VISIBILITY: a finding raised BEFORE the checks ran (containment refused,
    # an unsupported platform, a rejected findings record) carried its reason code only on the
    # finding itself. A consumer following "read the reason codes" therefore saw downstream
    # symptoms — SEM_MUTATION_BELOW_THRESHOLD on a run where mutation never executed — and not
    # the actual cause. Every incoming blocking finding's code is hoisted to the top level.
    for f in findings:
        if f.reason_code and f.blocks and R.is_valid(f.reason_code):
            reason_codes.append(f.reason_code)

    # --- checks ----------------------------------------------------------------------------
    ctx = EvalContext(evidence_set, findings, profile, subject, round_index, clean_round_streak)
    check_results = []
    for spec in profile.checks:
        fn = REGISTRY.get(spec.evaluator)
        if fn is None:
            raise SemanticEngineError(
                f"profile {profile.id!r} names unknown evaluator {spec.evaluator!r}")
        applicable, resolved = applies(spec.applies_when, evidence_set)
        if not applicable:
            check_results.append(CheckResult(
                check_id=spec.id, title=spec.title, passed=True, required=spec.required,
                showstopper=spec.showstopper, evidence_kind=spec.evidence_kind.value,
                reason_code=None,
                detail=f"not applicable: condition {spec.applies_when!r} is not met"))
            continue
        ev = _pick(evidence_set, spec.evidence_kind)
        # FIX-ENGINE-EVALUATOR-CRASH: an evaluator that raises on a hostile or merely
        # unexpected payload shape must not take the whole decision down with it. A crash is
        # converted into a FAILED check carrying EVD_MALFORMED, which is the fail-closed
        # answer: we could not read the evidence, therefore the check did not pass.
        try:
            passed, code, detail = fn(ev, spec, ctx)
        except Exception as exc:  # noqa: BLE001 — deliberate: any failure becomes a failed check
            passed, code = False, R.EVD_MALFORMED
            detail = (f"evaluator {spec.evaluator!r} could not read the evidence "
                      f"({type(exc).__name__}: {exc})")
        if not resolved and spec.applies_when != "always":
            detail = (f"{detail} [condition {spec.applies_when!r} could not be resolved; "
                      f"evaluated as APPLICABLE]")
        check_results.append(CheckResult(
            check_id=spec.id, title=spec.title, passed=bool(passed),
            required=spec.required, showstopper=spec.showstopper,
            evidence_kind=spec.evidence_kind.value, reason_code=code, detail=detail))
        if not passed and spec.required:
            reason_codes.append(code or R.SEM_REQUIRED_CHECK_FAILED)
            reason_codes.append(
                R.SEM_SHOWSTOPPER_OPEN if spec.showstopper else R.SEM_REQUIRED_CHECK_FAILED)

    # --- thresholds --------------------------------------------------------------------------
    threshold_results = []
    for th in profile.thresholds:
        applicable, _resolved = applies(th.applies_when, evidence_set)
        if not applicable:
            threshold_results.append(ThresholdResult(
                threshold_id=th.id, metric=th.metric, comparison=th.comparison.value,
                required_value=th.value, measured_value=None, passed=True,
                required=False, unit=th.unit, reason_code=None))
            continue
        try:
            measured = _measure(evidence_set, th)
        except Exception:  # noqa: BLE001 — an unreadable metric is UNMEASURED, never zero
            measured = None
        ok, code = th.satisfied_by(measured)
        threshold_results.append(ThresholdResult(
            threshold_id=th.id, metric=th.metric, comparison=th.comparison.value,
            required_value=th.value, measured_value=measured, passed=bool(ok),
            required=th.required, unit=th.unit, reason_code=code))
        if not ok:
            reason_codes.append(code)
            if th.metric == "mutation_score_pct":
                reason_codes.append(R.SEM_MUTATION_BELOW_THRESHOLD)

    # --- structured outcomes carried in the decision --------------------------------------
    cujs = _cuj_outcomes(evidence_set)
    heldout = _heldout_outcomes(evidence_set)
    for h in heldout:
        if h.bound and not h.evaluated:
            reason_codes.append(R.SEM_HELDOUT_NOT_EVALUATED)

    # --- status ------------------------------------------------------------------------------
    failing = [c for c in reason_codes if c in R.SEMANTIC_FAILING]
    status = SemanticStatus.FAILED if failing else SemanticStatus.PASSED

    break_glass = None
    if policy.break_glass.active:
        # An override is recorded, never applied. The status stays FAILED so the run can
        # never be presented as VERIFIED; the consumer decides what to do with it.
        break_glass = policy.break_glass.to_json()
        reason_codes.append(R.OPS_BREAK_GLASS)
        if status is SemanticStatus.PASSED:
            # Break-glass on a passing run is meaningless but must not silently vanish.
            break_glass = dict(break_glass, note="override recorded; the run passed on its merits")
        else:
            break_glass = dict(break_glass, note="override recorded; the semantic status remains FAILED")

    if status is SemanticStatus.PASSED:
        reason_codes.append(R.SEM_ALL_REQUIRED_CHECKS_PASSED)
    reason_codes.append({
        Mode.ADVISORY: R.OPS_MODE_ADVISORY,
        Mode.OBSERVE: R.OPS_MODE_OBSERVE,
        Mode.ENFORCE: R.OPS_MODE_ENFORCE,
    }[policy.mode])

    containment_ev = evidence_set.first(EvidenceKind.CONTAINMENT)
    containment = dict(containment_ev.payload) if containment_ev else {
        "boundary": {"kind": "unknown", "established": False},
        "allTargetContained": False,
        "note": "no containment evidence was collected",
    }
    containment.pop("invocations", None)  # keep the decision bounded; the ledger digest stays

    # --- self-attested phase coverage (may only SUBTRACT) --------------------------------
    #
    # Deliberately the LAST thing computed and deliberately after `status`. Nothing below
    # reads `coverage`, and `status` above never saw it: a self-report cannot reach the
    # semantic status by any path, including an accidental one. What it can do is add
    # informational COV_* codes — none of which is in `SEMANTIC_FAILING`, so appending them
    # cannot flip a PASSED run — and qualify how the outcome READS.
    coverage = build_coverage(phase_claims, source=coverage_source, note=coverage_note,
                              corroborated=_corroborated_phases(evidence_set, check_results))
    reason_codes.extend(coverage.reason_codes())

    return Decision(
        decision_id=decision_id or f"sgd_{uuid.uuid4().hex}",
        created_at=utcnow_iso(),
        subject=subject,
        profile_id=profile.id,
        profile_digest=profile.digest(),
        semantic_status=status,
        reason_codes=tuple(_dedupe(reason_codes)),
        checks=tuple(check_results),
        thresholds=tuple(threshold_results),
        cujs=tuple(cujs),
        heldout=tuple(heldout),
        findings=tuple(findings),
        required_evidence=tuple(k.value for k in profile.required_evidence),
        received_evidence=tuple(_received(evidence_set)),
        input_digests=tuple(evidence_set.input_digests()),
        containment=containment,
        coverage=coverage,
        break_glass=break_glass,
        mode=policy.mode.value,
        residual_risk=residual_risk,
    )


# --- helpers ----------------------------------------------------------------------------------

def _dedupe(seq):
    return list(dict.fromkeys(seq))


def _pick(evidence_set, kind):
    """The evidence a check should read.

    When several collectors produced the same kind, prefer a COLLECTED one; the evidence
    gate has already flagged any genuine contradiction, so this only ever picks between
    agreeing observations.
    """
    evs = evidence_set.of_kind(kind)
    if not evs:
        return None
    for e in evs:
        if e.status is EvidenceStatus.COLLECTED:
            return e
    for e in evs:
        if e.status is EvidenceStatus.PARTIAL:
            return e
    return evs[0]


def _received(evidence_set):
    rows = []
    for e in sorted(evidence_set, key=lambda x: (x.kind.value, x.collector)):
        rows.append({
            "kind": e.kind.value,
            "collector": e.collector,
            "status": e.status.value,
            "collectedAt": e.collected_at,
            "uncovered": list(e.uncovered),
        })
    return rows


def _measure(evidence_set, threshold):
    """Read a metric out of its evidence. Returns None when unmeasured — never 0.

    Conflating "unmeasured" with "zero" is how a threshold silently passes; `Threshold`
    treats None as failing for a required threshold.
    """
    ev = _pick(evidence_set, threshold.evidence_kind)
    if ev is None or ev.status in (EvidenceStatus.ERROR, EvidenceStatus.ABSENT):
        return None
    p = ev.payload
    if not isinstance(p, dict):
        return None

    metric = threshold.metric
    direct = p.get(metric)
    if isinstance(direct, int) and not isinstance(direct, bool):
        return direct
    metrics = p.get("metrics")
    if isinstance(metrics, dict):
        v = metrics.get(metric)
        if isinstance(v, int) and not isinstance(v, bool):
            return v

    counts = p.get("counts") if isinstance(p.get("counts"), dict) else {}
    derived = {
        "undetected_faults": lambda: _len(p.get("undetected")),
        "serious_violations": lambda: _sum(counts, "serious", "critical"),
        "high_severity_findings": lambda: _sum(counts, "high", "critical"),
        "undetected_env_faults": lambda: _len(
            [o for o in (p.get("operators") or []) if o.get("applied") and not o.get("detected")]),
        "mutation_score_pct": lambda: _int_or_none(p.get("scorePct")),
    }
    fn = derived.get(metric)
    return fn() if fn else None


def _len(v):
    return len(v) if isinstance(v, list) else None


def _sum(counts, *keys):
    total = 0
    seen = False
    for k in keys:
        v = counts.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            total += v
            seen = True
    return total if seen else None


def _int_or_none(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _cuj_outcomes(evidence_set):
    ev = _pick(evidence_set, EvidenceKind.CUJ)
    if ev is None or not isinstance(ev.payload, dict):
        return []
    out = []
    for j in ev.payload.get("journeys") or []:
        out.append(CujOutcome(
            id=str(j.get("id", "?")), title=str(j.get("title", "")),
            status=str(j.get("status", "ERROR")).upper(),
            evidence_ref=j.get("evidenceRef"), detail=str(j.get("detail", ""))))
    return out


def _heldout_outcomes(evidence_set):
    ev = _pick(evidence_set, EvidenceKind.HELDOUT)
    if ev is None or not isinstance(ev.payload, dict):
        return []
    out = []
    for s in ev.payload.get("suites") or []:
        out.append(HeldOutOutcome(
            suite_id=str(s.get("suiteId", "?")),
            bound=bool(s.get("bound")),
            evaluated=bool(s.get("evaluated")),
            total=_coerce_int(s.get("total")),
            passed=_coerce_int(s.get("passed")),
            failed=_coerce_int(s.get("failed")),
            errored=_coerce_int(s.get("errored")),
            binding_digest=s.get("bindingDigest"),
            detail=str(s.get("detail", ""))))
    return out


def _coerce_int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


#: phase -> the evidence kind whose collector establishes it. All four agentic phases now
#: have one; each collector mechanises its phase's falsifiable floor and nothing above it.
PHASE_EVIDENCE = {
    "A2": EvidenceKind.REQUIREMENTS,
    "G2": EvidenceKind.DESIGN_CONFORMANCE,
    "G3": EvidenceKind.CROSS_SURFACE,
    "H": EvidenceKind.ADVERSARIAL_PROBE,
}


def _corroborated_phases(evidence_set, check_results):
    """Which agentic phases a COLLECTOR established. The only input that clears a caveat.

    The bar is deliberately both halves: the evidence must be COLLECTED (not PARTIAL, not
    ABSENT, not ERROR) AND the check over it must have PASSED. Either half alone is not
    corroboration — PARTIAL adversarial evidence means some of the attack surface was never
    reached, and a failed check means the phase ran and found something, which is a reason
    to keep the caveat rather than to drop it.

    Note what is NOT here: nothing reads a claim. A phase is corroborated by evidence or it
    is not corroborated at all, so the agent's own account can never be its own corroboration.
    """
    by_kind = {c.evidence_kind: c for c in check_results}
    out = []
    for phase, kind in sorted(PHASE_EVIDENCE.items()):
        ev = evidence_set.first(kind)
        if ev is None or ev.status is not EvidenceStatus.COLLECTED:
            continue
        check = by_kind.get(kind.value)
        if check is None or not check.passed:
            continue
        if "not applicable" in (check.detail or ""):
            continue
        out.append(phase)
    return tuple(out)


def _binding_from_subject(subject, evidence_set):
    from ..models.evidence import EvidenceBinding
    first = next(iter(evidence_set), None)
    return EvidenceBinding(
        run_id=first.binding.run_id if first else "",
        round_index=first.binding.round_index if first else 1,
        repository=subject.repository,
        commit=subject.commit,
        tree_digest=subject.tree_digest,
        artifact_id=subject.artifact_id,
        artifact_digest=subject.artifact_digest,
    )


__all__ = ["run_semantic_gate", "SemanticEngineError", "SubjectIdentity"]
