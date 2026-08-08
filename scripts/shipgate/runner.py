"""Run orchestration — requirements/profile -> collectors -> semantic core -> decision.

This module is the top of the SEMANTIC half. It knows about collectors, the engine and the
decision; it knows nothing about authority and imports none of it. `gate.py` sits above
`runner` and is the only place that may consult the optional authority kit — which is why
deleting `shipgate/authority/` leaves this file, and the VERIFIED workflow, untouched.
"""
import dataclasses
import json
import os
import uuid
from pathlib import Path
from typing import Optional, Tuple

from .collectors import (
    ALL_COLLECTORS, STATIC_COLLECTORS, CollectorContext, EvidenceCache, run_all,
    run_scheduled)
from .execadapter import ContainmentUnavailable, ExecutionAdapter
from .execadapter import containment as _containment
from .models import reasons as R
from .models.decision import SubjectIdentity
from .models.evidence import Evidence, EvidenceBinding, EvidenceKind, EvidenceSet
from .models.finding import Finding, FindingState, Severity
from .models.policy import Policy
from .models.profile import DEFAULT_PROFILE_ID, EscalationSignal
from .semantic.engine import run_semantic_gate
from .util.canonical import canonical_bytes, loads_strict
from .util.hashing import tree_digest
from .version import SUPPORTED_PLATFORMS

WORKDIR_NAME = "shipgate-workdir"


@dataclasses.dataclass(frozen=True)
class RunRequest:
    repo: str
    run_area: Optional[str] = None
    profile_id: str = DEFAULT_PROFILE_ID
    policy: Policy = dataclasses.field(default_factory=Policy)
    run_id: Optional[str] = None
    round_index: int = 1
    escalation_signals: Tuple[EscalationSignal, ...] = ()
    profile_recommendations: Tuple[str, ...] = ()
    artifact_path: Optional[str] = None
    residual_risk: str = ""
    static_only: bool = False
    #: SELF-ATTESTED phase claims: {"H": "run", "A2": "not_run", ...}. Supplied by the
    #: operating agent, believed only in the direction that SUBTRACTS confidence, and never
    #: able to raise a status — see models/coverage.py. `None` means "read phases.json from
    #: the workdir if it is there", which is not the same as "assume the phases ran": a run
    #: with no phase information gets the conservative record, identical to one that said it
    #: did none of them.
    phase_claims: Optional[dict] = None
    options: dict = dataclasses.field(default_factory=dict)
    #: Named parent-environment variables the operator explicitly forwards into the boundary.
    #: FIX-PROXY-CA: the env allowlist correctly drops HTTPS_PROXY / NODE_EXTRA_CA_CERTS, which
    #: made `npm audit` unusable behind a corporate proxy with a custom CA and turned a working
    #: environment into a SHOWSTOPPER with no supported remedy. Forwarding is now explicit,
    #: opt-in, per-name, and still refused for secret-shaped names (see execadapter.env).
    allow_env: Tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class RunResult:
    decision: object          # models.decision.Decision
    evidence: EvidenceSet
    workdir: str
    run_area: str
    containment: dict


def run(request):
    """Execute one full semantic gate run and return an immutable Decision.

    Never raises for a *gate* outcome: a refusal to run (no containment) becomes a FAILED
    decision carrying EXE_CONTAINMENT_REFUSED, because "the gate could not safely run" is a
    result the caller must be able to consume, not an unhandled traceback.
    """
    repo = Path(request.repo).resolve()
    run_area = Path(request.run_area).resolve() if request.run_area else repo
    workdir = run_area / WORKDIR_NAME
    workdir.mkdir(parents=True, exist_ok=True)

    run_id = request.run_id or f"sgr_{uuid.uuid4().hex[:16]}"
    subject = _subject(repo, run_area, request.artifact_path)
    binding = EvidenceBinding(
        run_id=run_id, round_index=request.round_index, repository=subject.repository,
        commit=subject.commit, tree_digest=subject.tree_digest,
        artifact_id=subject.artifact_id, artifact_digest=subject.artifact_digest)

    preflight = list(_platform_findings())

    # --- containment resolved before a single target process is spawned -------------------
    record = _containment.detect(accepted=tuple(request.policy.containment.accepted))
    try:
        adapter = ExecutionAdapter(run_area, request.policy, containment_record=record,
                                   allow_env=request.allow_env)
        adapter.require_boundary()
        refused = None
    except ContainmentUnavailable as exc:
        refused = exc
        adapter = None

    evidence = EvidenceSet()

    if refused is not None:
        evidence.add(Evidence.error(
            EvidenceKind.CONTAINMENT, "execadapter", "4.2.4", binding,
            note=str(refused),
            payload={"boundary": record, "containmentRequired": True,
                     "allTargetContained": False, "anyTargetExecuted": False,
                     "targetInvocations": 0, "uncontainedTargetInvocations": 0,
                     "refused": True}))
        preflight.append(Finding(
            id="EXE-001", severity=Severity.SHOWSTOPPER, state=FindingState.OPEN,
            title="Execution containment unavailable",
            detail=str(refused), source="execadapter",
            reason_code=R.EXE_CONTAINMENT_REFUSED))
    else:
        ctx = CollectorContext(repo=str(repo), run_area=str(run_area), workdir=str(workdir),
                               binding=binding, adapter=adapter,
                               options=dict(request.options,
                                            allow_env=list(request.allow_env)))
        collectors = [c() for c in (STATIC_COLLECTORS if request.static_only
                                    else ALL_COLLECTORS)]
        evidence_cache = EvidenceCache(request.policy.cache, binding,
                                       options=request.options, run_area=str(run_area))
        run_scheduled(_cached(collectors, evidence_cache), ctx, evidence,
                      parallelism=request.policy.parallelism)
        evidence.add(Evidence.collected(
            EvidenceKind.CONTAINMENT, "execadapter", "4.2.4", binding,
            adapter.containment_payload()))

    findings = preflight + _load_findings(workdir)
    phase_claims, coverage_source, coverage_note = _load_phase_claims(request, workdir)

    # --- convergence -----------------------------------------------------------------------
    #
    # FIX-CLEAN-ROUND-MEANS-PASSED: a round was recorded "clean" when it had zero blocking
    # FINDINGS. That is not the same as passing. A round could fail every required check —
    # missing evidence, an unmet threshold, a dead CUJ — raise no *finding* record, exit 1,
    # and still be counted toward the two-consecutive-clean-rounds requirement. Convergence
    # could therefore be satisfied by one failing round plus one passing one, which is a
    # fail-open in the one place the gate is supposed to insist on stability.
    #
    # A round is clean if and only if the decision would have PASSED on its own merits —
    # every required check and threshold satisfied, no blocking finding — with the
    # convergence check itself excluded, since it is the thing being decided.
    #
    # The engine is pure and does no I/O, so it is evaluated twice: once to establish
    # cleanliness, once with the resulting streak. Both evaluations see identical inputs, so
    # this costs nothing in determinism.
    def _evaluate(streak_value):
        return run_semantic_gate(
            evidence, findings,
            subject=subject,
            profile_id=request.profile_id,
            escalation_signals=request.escalation_signals,
            profile_recommendations=request.profile_recommendations,
            policy=request.policy,
            round_index=request.round_index,
            clean_round_streak=streak_value,
            residual_risk=request.residual_risk,
            expected_binding=binding,
            phase_claims=phase_claims,
            coverage_source=coverage_source,
            coverage_note=coverage_note,
        )

    probe = _evaluate(_CONVERGENCE_SATISFIED)
    clean_now = _round_is_clean(probe)
    blocking_now = _blocking_count(probe)

    history = _round_history(workdir)
    streak = _clean_round_streak(history, request.round_index, clean_now)
    decision = _evaluate(streak)

    _record_round(workdir, history, request.round_index, clean_now, blocking_now)
    _persist(workdir, decision, evidence)
    _persist_run_metadata(workdir, decision, request, evidence_cache if adapter else None)
    return RunResult(decision=decision, evidence=evidence, workdir=str(workdir),
                     run_area=str(run_area),
                     containment=(adapter.containment if adapter else record))


def _cached(collectors, evidence_cache):
    """Wrap each collector so a cache hit short-circuits its `run`.

    Transparent to the scheduler: `kind`, `name` and `version` are forwarded, which is all the
    scheduler reads. A miss, a refusal, or a disabled cache all fall through to the real
    collector, so the cache can only ever remove WORK — never change an ANSWER.
    """
    class _Wrapped:
        def __init__(self, inner):
            self._inner = inner
            self.kind, self.name, self.version = inner.kind, inner.name, inner.version

        def run(self, ctx):
            hit = evidence_cache.get(self._inner)
            if hit is not None:
                return hit
            ev = self._inner.run(ctx)
            evidence_cache.put(self._inner, ev)
            return ev

    return [_Wrapped(c) for c in collectors]


# --- helpers -------------------------------------------------------------------------------

def _platform_findings():
    """Declare the supported surface honestly. An unsupported platform is recorded, and it
    fails the run — a gate that cannot vouch for its own execution environment must not
    vouch for a release."""
    import platform
    tag = f"{platform.system().lower()}-{platform.machine()}"
    normalised = tag.replace("amd64", "x86_64")
    if normalised not in SUPPORTED_PLATFORMS:
        yield Finding(
            id="PLT-001", severity=Severity.SHOWSTOPPER, state=FindingState.OPEN,
            title="Unsupported execution platform",
            detail=(f"running on {normalised!r}; this release declares support for "
                    f"{', '.join(SUPPORTED_PLATFORMS)} only. Other platforms are not tested "
                    "and are not claimed."),
            source="runner", reason_code=R.OPS_PLATFORM_UNSUPPORTED)


def _subject(repo, run_area, artifact_path):
    commit = _head_commit(run_area) or _head_commit(repo) or "0" * 40
    digest = tree_digest(run_area)
    artifact_id = artifact_digest = None
    if artifact_path:
        p = Path(artifact_path)
        if p.is_file():
            from .util.hashing import sha256_file
            artifact_id, artifact_digest = p.name, sha256_file(p)
        elif p.is_dir():
            artifact_id, artifact_digest = p.name, tree_digest(p)
    if artifact_digest is None:
        # With no separate build artifact, the tree IS the artifact. Saying so explicitly
        # keeps evidence non-transferable between builds.
        artifact_id, artifact_digest = "source-tree", digest
    return SubjectIdentity(
        repository=_repo_name(repo), commit=commit, tree_digest=digest,
        artifact_id=artifact_id, artifact_digest=artifact_digest,
        branch=_branch(run_area))


def _repo_name(repo):
    return Path(repo).name or str(repo)


def _git_file(area, *parts):
    """Read git state from the filesystem rather than by running git.

    The runner resolves identity before the execution adapter exists, and shelling out here
    would be a process spawn outside the chokepoint. Reading `.git` directly is both safer
    and independent of a `git` binary being installed.
    """
    g = Path(area) / ".git"
    if g.is_file():
        try:
            text = g.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        if text.startswith("gitdir:"):
            g = Path(text.split(":", 1)[1].strip())
            if not g.is_absolute():
                g = (Path(area) / g).resolve()
    p = g.joinpath(*parts)
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _head_commit(area):
    head = _git_file(area, "HEAD")
    if not head:
        return None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        sha = _git_file(area, *ref.split("/"))
        if sha:
            return sha
        packed = _git_file(area, "packed-refs") or ""
        for line in packed.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
        return None
    return head if len(head) == 40 else None


def _branch(area):
    head = _git_file(area, "HEAD")
    if head and head.startswith("ref:"):
        return head.split("/", 2)[-1].strip()
    return None


def _load_phase_claims(request, workdir):
    """(claims, source, note) — what the operating agent says it did.

    Precedence: an explicit `request.phase_claims` beats the file, because a caller that
    passed claims in has already decided. `phases.json` in the workdir is the file form,
    matching how `findings.json` and `cujs.json` already work.

    A MALFORMED FILE IS NOT AN ERROR AND NOT AN EMPTY RECORD. It becomes the conservative
    record — every phase `not_run` — with the problem stated in the note. That is the only
    reading that stays safe in both directions: refusing the run would let a typo block a
    gate over something that cannot fail anything, and dropping the block would make a
    broken claim indistinguishable from no claim, which is the more permissive of the two.
    """
    if request.phase_claims is not None:
        return dict(request.phase_claims), "caller", ""
    path = Path(workdir) / "phases.json"
    if not path.exists():
        return {}, "operating_agent", ("no phases.json was supplied; every agentic phase is "
                                       "recorded as not run")
    try:
        doc = loads_strict(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {}, "operating_agent", (f"phases.json is unreadable ({type(exc).__name__}: "
                                       f"{exc}); recorded conservatively as not run")
    if isinstance(doc, dict) and isinstance(doc.get("phases"), dict):
        return dict(doc["phases"]), str(doc.get("source") or "operating_agent"), \
            str(doc.get("note") or "")
    if isinstance(doc, dict):
        return dict(doc), "operating_agent", ""
    return {}, "operating_agent", ("phases.json is not an object; recorded conservatively "
                                   "as not run")


def _load_findings(workdir):
    """Read operator-recorded findings. A malformed file is a SHOWSTOPPER, not an empty list:
    silently starting from zero findings is exactly how a fake pass happens."""
    p = Path(workdir) / "findings.json"
    if not p.exists():
        return []
    try:
        doc = loads_strict(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [Finding(id="FND-000", severity=Severity.SHOWSTOPPER, state=FindingState.OPEN,
                        title="findings.json is unreadable",
                        detail=f"{type(exc).__name__}: {exc}", source="runner",
                        reason_code=R.EVD_MALFORMED)]
    # FIX-FINDINGS-SHAPE: accept BOTH the object form {"findings":[...]} and the bare
    # array form [...] — `collectors/findings.py` already accepts the array, and two loaders
    # disagreeing about the file format is a defect in itself. Anything else is rejected as a
    # showstopper rather than silently read as "no findings", which is how a fake pass starts.
    if isinstance(doc, list):
        rows = doc
    elif isinstance(doc, dict):
        rows = doc.get("findings")
        if rows is None:
            rows = []
        elif not isinstance(rows, list):
            return [Finding(id="FND-000", severity=Severity.SHOWSTOPPER,
                            state=FindingState.OPEN, title="findings.json is malformed",
                            detail=f"'findings' must be an array, got {type(rows).__name__}",
                            source="runner", reason_code=R.EVD_MALFORMED)]
    else:
        return [Finding(id="FND-000", severity=Severity.SHOWSTOPPER, state=FindingState.OPEN,
                        title="findings.json is malformed",
                        detail=(f"expected an object with a 'findings' array, or a bare array; "
                                f"got {type(doc).__name__}"),
                        source="runner", reason_code=R.EVD_MALFORMED)]

    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            out.append(Finding(
                id=f"FND-BAD-{i:03d}", severity=Severity.SHOWSTOPPER,
                state=FindingState.OPEN, title="Rejected finding record",
                detail=f"entry {i} is {type(row).__name__}, expected an object",
                source="runner", reason_code=R.EVD_MALFORMED))
            continue
        try:
            out.append(Finding(
                id=str(row.get("id", f"FND-{i:03d}")),
                severity=Severity(str(row.get("severity", "MAJOR")).upper()),
                state=FindingState(str(row.get("state", "OPEN")).upper()),
                title=str(row.get("title", "")), detail=str(row.get("detail", "")),
                source=str(row.get("source", "operator")),
                reason_code=row.get("reasonCode"), location=row.get("location"),
                evidence_refs=tuple(row.get("evidenceRefs") or []),
                reason=row.get("reason"), authority=row.get("authority"),
                cuj=bool(row.get("cuj"))))
        except (ValueError, KeyError) as exc:
            # A refused waiver lands here — record it as an open showstopper rather than
            # dropping the row, so an attempt to waive the unwaivable is visible.
            out.append(Finding(
                id=f"FND-BAD-{i:03d}", severity=Severity.SHOWSTOPPER,
                state=FindingState.OPEN, title="Rejected finding record",
                detail=f"{exc}", source="runner", reason_code=R.EVD_MALFORMED))
    return out


ROUNDS_FILE = "rounds.json"

#: Streak value used for the probe evaluation. Large enough that the convergence check can
#: never be the thing that fails, so the probe measures the round ON ITS OWN MERITS.
_CONVERGENCE_SATISFIED = 1_000_000

#: The check whose failure is EXCLUDED when deciding whether a round was clean — it is the
#: check that consumes the answer, so including it would make the streak self-referential.
_CONVERGENCE_CHECK_ID = "findings.none_blocking"


def _round_is_clean(decision):
    """True iff this round passed on its own merits.

    Deliberately derived from the DECISION, not from the finding list: a round that failed a
    required check without raising a finding record is not clean, and reading only findings
    is exactly how the fail-open arose.

    The convergence check is excluded, because it is the check that CONSUMES this answer.
    Including it would make the streak self-referential and it could never begin: round one
    always fails convergence, so round one would never be clean, so there would never be a
    round two with a streak. The runner also probes with a satisfied streak, so this
    exclusion is belt-and-braces — it keeps the function correct when called directly.
    """
    for c in decision.checks:
        if c.check_id == _CONVERGENCE_CHECK_ID:
            continue
        if c.required and not c.passed:
            return False
    for t in decision.thresholds:
        if t.required and not t.passed:
            return False
    return not any(f.blocks for f in decision.findings)


def _blocking_count(decision):
    """How much was wrong this round — for the history record, not for the decision."""
    failed_checks = sum(1 for c in decision.checks
                        if c.required and not c.passed and c.check_id != _CONVERGENCE_CHECK_ID)
    failed_thresholds = sum(1 for t in decision.thresholds if t.required and not t.passed)
    blocking_findings = sum(1 for f in decision.findings if f.blocks)
    return failed_checks + failed_thresholds + blocking_findings


def _round_history(workdir):
    """Gate-owned round history. Never the operator's file.

    FIX-CONVERGENCE-UNREACHABLE: the clean-round streak was read from the FINDINGS evidence,
    which computed it from a `rounds` array in the operator's `findings.json` — but NOTHING
    EVER WROTE THAT ARRAY. Since both profiles require two consecutive clean rounds, the
    streak could never exceed 1 and **no run could ever reach VERIFIED** unless the operator
    hand-authored round history that the documentation told them not to touch. The history is
    now gate-owned, written by the runner after each round, and keyed by round index so a
    re-run of the same round replaces its record rather than inflating the streak.
    """
    p = Path(workdir) / ROUNDS_FILE
    if not p.exists():
        return []
    try:
        doc = loads_strict(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — unreadable history is NO history, never a free streak
        return []
    rounds = doc.get("rounds") if isinstance(doc, dict) else None
    if not isinstance(rounds, list):
        return []
    out = []
    for r in rounds:
        if isinstance(r, dict) and isinstance(r.get("round"), int) \
                and isinstance(r.get("clean"), bool):
            out.append({"round": r["round"], "clean": r["clean"],
                        "blocking": r.get("blocking", 0), "at": r.get("at", "")})
    out.sort(key=lambda r: r["round"])
    return out


def _clean_round_streak(history, round_index, clean_now):
    """Consecutive clean rounds ending at (and including) this one.

    Only rounds STRICTLY BEFORE this one count as history, so re-running round N cannot
    accumulate. A single dirty round resets the streak to zero — that is the whole point.
    """
    if not clean_now:
        return 0
    streak = 1
    for r in reversed([r for r in history if r["round"] < round_index]):
        if r["clean"]:
            streak += 1
        else:
            break
    return streak


def _record_round(workdir, history, round_index, clean, blocking):
    kept = [r for r in history if r["round"] != round_index]
    kept.append({"round": round_index, "clean": bool(clean), "blocking": int(blocking),
                 "at": _now()})
    kept.sort(key=lambda r: r["round"])
    p = Path(workdir) / ROUNDS_FILE
    p.write_bytes(canonical_bytes({
        "schema": "shipgate.rounds/1",
        "note": ("Gate-owned round history. The runner writes this; do not hand-edit it. A "
                 "round is CLEAN only if the decision would have passed on its own merits — "
                 "every required check and threshold satisfied and no blocking finding, with "
                 "the convergence check itself excluded because it consumes this answer. "
                 "Zero blocking findings is NOT sufficient: a round can fail a required check "
                 "without raising a finding record."),
        "rounds": kept,
    }))
    return kept


def _now():
    from .util.clock import utcnow_iso
    return utcnow_iso()


def _persist_run_metadata(workdir, decision, request, evidence_cache):
    """How the run was EXECUTED, written beside the decision rather than inside it.

    Parallelism and cache behaviour are properties of THIS EXECUTION, not of the subject under
    evaluation. Putting them in the decision would make the decision digest depend on the
    worker count and on whether a cache happened to be warm — so a consumer pinning a digest
    in CI would see it break the moment somebody tuned `--parallelism`, for no semantic reason
    at all. The digest must track what was decided, not how fast it was decided.

    They are still recorded, and bound to the decision digest, because a run that quietly
    reused an old observation must not be indistinguishable from one that made a fresh one.
    Same reasoning as `attestation.json`: additive, adjacent, never inside.
    """
    body = {
        "schema": "shipgate.run-metadata/1",
        "decisionDigest": decision.digest(),
        "parallelism": int(request.policy.parallelism),
        "mode": request.policy.mode.value,
        "cache": evidence_cache.summary() if evidence_cache else {"enabled": False},
        "note": ("Execution metadata. Deliberately OUTSIDE the decision: the decision digest "
                 "must not change because a run used more workers or a warm cache."),
    }
    (Path(workdir) / "run-metadata.json").write_bytes(canonical_bytes(body))


def _persist(workdir, decision, evidence):
    wd = Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "decision.json").write_bytes(canonical_bytes(decision.to_envelope()))
    (wd / "evidence.json").write_bytes(canonical_bytes(evidence.to_json()))
    (wd / "decision.digest").write_text(decision.digest() + "\n", encoding="utf-8")
