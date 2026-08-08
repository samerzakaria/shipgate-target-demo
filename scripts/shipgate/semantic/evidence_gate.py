"""Pre-check evidence validation — the fail-closed frontier.

Before a single check runs, the evidence set must survive this. Missing, stale, malformed,
contradictory, incomplete or mismatched required evidence fails the decision closed; it is
never treated as "not applicable".

Returned as a list of `(reason_code, detail)` pairs. A non-empty list means the semantic
status is FAILED regardless of what the checks would have said.
"""
from ..models import reasons as R
from ..models.evidence import EvidenceStatus


def validate(evidence_set, profile, expected_binding):
    from .checks import applies

    problems = []

    # 0. Resolve conditional requirements. An unresolvable condition resolves to REQUIRED,
    #    so a crashed stack detector can never shrink the evidence requirement.
    required_kinds = list(profile.required_evidence)
    for cond in getattr(profile, "conditional_evidence", ()):
        applicable, resolved = applies(cond.applies_when, evidence_set)
        if applicable:
            required_kinds.append(cond.kind)
            if not resolved:
                problems.append((R.EVD_INCOMPLETE,
                                 f"could not resolve condition {cond.applies_when!r} for "
                                 f"{cond.kind.value}; treating it as REQUIRED"))

    # 1. Required evidence must be present AND usable.
    present = {}
    for kind in dict.fromkeys(required_kinds):
        evs = evidence_set.of_kind(kind)
        if not evs:
            problems.append((R.EVD_REQUIRED_MISSING,
                             f"required evidence {kind.value} was never collected"))
            continue
        present[kind] = evs
        if all(e.status is EvidenceStatus.ERROR for e in evs):
            notes = "; ".join(e.note for e in evs if e.note)[:200]
            problems.append((R.EVD_COLLECTOR_ERROR,
                             f"required evidence {kind.value}: every collector errored ({notes})"))
        elif all(e.status is EvidenceStatus.ABSENT for e in evs):
            problems.append((R.EVD_REQUIRED_MISSING,
                             f"required evidence {kind.value}: reported absent"))

    # 2. Freshness. An unparseable timestamp is NOT fresh — it is unreadable, so it fails.
    for kind, evs in present.items():
        for e in evs:
            stale = e.is_stale(profile.max_evidence_age_seconds)
            if stale is None:
                problems.append((R.EVD_MALFORMED,
                                 f"{kind.value}/{e.collector}: unreadable collectedAt "
                                 f"{e.collected_at!r}"))
            elif stale:
                problems.append((R.EVD_STALE,
                                 f"{kind.value}/{e.collector}: collected at {e.collected_at}, "
                                 f"older than the {profile.max_evidence_age_seconds}s limit "
                                 f"(or dated in the future)"))

    # 3. Binding. Evidence about a different run, repo, commit or artifact is not evidence
    #    about this release.
    for mm in evidence_set.binding_mismatches(expected_binding):
        for field, (want, got) in sorted(mm["diff"].items()):
            code = {
                "runId": R.EVD_RUN_MISMATCH,
                "commit": R.EVD_COMMIT_MISMATCH,
                "artifactDigest": R.EVD_ARTIFACT_MISMATCH,
            }.get(field, R.EVD_RUN_MISMATCH)
            problems.append((code,
                             f"{mm['kind']}/{mm['collector']}: {field} expected {want!r}, "
                             f"evidence carries {got!r}"))

    # 4. Contradiction. Two collectors of the same kind that disagree cannot both be right,
    #    and picking one would be arbitrary.
    for c in evidence_set.contradictions():
        problems.append((R.EVD_CONTRADICTORY,
                         f"{c['kind']}: collectors {', '.join(c['collectors'])} produced "
                         f"different payloads"))

    # 5. Schema. Evidence produced by a different evidence schema version is not comparable.
    for e in evidence_set:
        if e.schema != _expected_schema():
            problems.append((R.EVD_UNSUPPORTED_SHAPE,
                             f"{e.kind.value}/{e.collector}: evidence schema {e.schema!r} is not "
                             f"{_expected_schema()!r}"))

    return problems


def _expected_schema():
    from ..version import EVIDENCE_SCHEMA_VERSION
    return EVIDENCE_SCHEMA_VERSION
