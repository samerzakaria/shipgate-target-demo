"""ONE place where the external policy is enforced. Every field, or the field is not in the
schema.

WHY A SINGLE MODULE. v4.1 loaded the policy in `policy.py`, checked verifier membership in
`live.py`, checked principal separation in `contracts.py`, and parsed — but never enforced —
`authorizedBuilders`, `requiredEnvironment` and the validity window. A field that is parsed
and not enforced is worse than one that is absent: it reads as a constraint and constrains
nobody. v4.2 finishes the enforcement and puts all of it here, so the question "what does the
policy actually do" has one answer in one file.

THE CONTRACT. `enforce_award` is called by `contracts.evaluate` with everything the verifiers
established, and returns which policy checks passed, which failed, and the AUT_* codes for the
failures. A failed check DEMOTES the award below INDEPENDENTLY_ATTESTED — it never merely
attaches a warning. `verifier_authorized` is the membership half used at observation time by
`live.verify_verifier_identity`; it is the same normalisation and the same list, so the two
sites cannot drift.

WHAT NORMALISATION MEANS HERE, precisely: strip surrounding whitespace, strip one trailing
`/`, and lower-case ONLY the scheme+host and the owner/repository segments of a
`https://github.com/...` workflow identity (GitHub treats those as case-insensitive; the
workflow path and the ref are case-sensitive and stay untouched). After that, membership is
EXACT string equality — never a prefix, a regexp, or a contains. A near-miss is a miss.

EXTERNAL TIME. The validity window is judged against a timestamp that something OUTSIDE the
verifier signed: a Rekor `integratedTime` whose checkpoint verified against the pinned log
key, or a platform-signed timestamp from a supported attestation path. The verifier's own
wall clock is never accepted — the party being constrained by `notAfter` must not supply the
clock that decides whether `notAfter` has passed. A window with no external time is a REFUSAL
(`AUT_POLICY_WINDOW_INVALID`), not a skipped check.
"""
import re
from typing import Any, Dict, Optional, Tuple

from ..models import reasons as R

#: Sources this kit accepts as EXTERNALLY ESTABLISHED time. Anything else — most importantly
#: the local clock and any operator-typed value — is not on the list and cannot get on it
#: from configuration.
EXTERNAL_TIME_SOURCES = (
    "rekor-integrated-time",       # checkpoint-verified Rekor entry integratedTime
    "github-attestation-tlog",     # tlog timestamp from a gh-verified attestation bundle
    "github-run-timestamp",        # platform-reported workflow run timestamp (signed path)
)

_GITHUB_WORKFLOW = re.compile(
    r"^(?P<host>https://github\.com/)(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<rest>.+)$")


def normalise_identity(identity: str) -> str:
    """One spelling per identity, and only the case-insensitive parts are folded."""
    value = (identity or "").strip()
    if value.endswith("/"):
        value = value[:-1]
    match = _GITHUB_WORKFLOW.match(value)
    if match:
        return (match.group("host").lower() + match.group("owner").lower() + "/"
                + match.group("repo").lower() + "/" + match.group("rest"))
    return value


def _member(candidates, identity: str) -> bool:
    wanted = normalise_identity(identity)
    return bool(wanted) and any(normalise_identity(c) == wanted for c in candidates or ())


def verifier_authorized(policy: Dict[str, Any], identity: str) -> Tuple[bool, str]:
    """Is this externally authenticated identity on the policy's authorizedVerifiers list?

    A `key:<sha256digest>` identity may appear here too: a self-issued key proves possession,
    not identity, so it can never authorise itself — but a key EXPLICITLY PINNED by the
    externally signed policy has been vouched for by the policy root, which is an external
    trust decision. The pin must be the exact `key:` string; there is no wildcard form.
    """
    if not identity:
        return False, "no verifier identity to check against the policy"
    if _member(policy.get("authorizedVerifiers"), identity):
        return True, (f"{identity!r} is an authorised verifier in policy version "
                      f"{policy.get('version')} for {policy.get('repository')}")
    return False, (f"{identity!r} is not in the policy's authorizedVerifiers for "
                   f"{policy.get('repository')} (version {policy.get('version')})")


def builder_authorized(policy: Dict[str, Any], builder_identity: str) -> Tuple[bool, str]:
    """Is the EXTERNALLY VERIFIED builder identity on the policy's authorizedBuilders list?

    The identity handed in here must come from verified provenance — a Fulcio certificate SAN
    that cosign checked, or a gh-verified attestation's certificate — never from repository
    configuration, a CLI argument, an environment variable, state.json, an unverified claim
    file, or any manifest the target repository supplies. The CALLER guarantees provenance;
    this function guarantees membership. If no verified builder identity exists, the answer
    is no, with a reason that says what is missing rather than pretending it was checked.
    """
    if not builder_identity:
        return False, ("no externally verified builder identity exists, so the policy's "
                       "authorizedBuilders constraint cannot be satisfied; independence is "
                       "unavailable rather than assumed")
    if _member(policy.get("authorizedBuilders"), builder_identity):
        return True, (f"builder {builder_identity!r} is authorised by policy version "
                      f"{policy.get('version')}")
    return False, (f"builder {builder_identity!r} is not in the policy's authorizedBuilders "
                   f"for {policy.get('repository')} (version {policy.get('version')})")


def environment_matches(policy: Dict[str, Any],
                        observed_environment: Optional[str]) -> Tuple[bool, str]:
    """policy.requiredEnvironment == the environment that was OBSERVED, not configured.

    The observed name must come from a live or signed-replay GitHub observation (and, once
    deployment evidence is bound, from the deployment record) — never from only the target
    repository's own configuration, which the party being judged writes.
    """
    required = (policy.get("requiredEnvironment") or "").strip()
    if not required:
        return False, ("the policy names no requiredEnvironment; schema/1 requires one and "
                       "the loader should have refused this document")
    observed = (observed_environment or "").strip()
    if not observed:
        return False, (f"the policy requires environment {required!r} but no environment was "
                       f"observed at all")
    if observed != required:
        return False, (f"the policy requires environment {required!r} but the observed "
                       f"environment is {observed!r}")
    return True, f"the observed environment {observed!r} is the policy-required environment"


def repository_id_matches(policy: Dict[str, Any],
                          observed_repository_id: Optional[Any]) -> Tuple[bool, str]:
    """When the policy pins a numeric repository id, the observed repository must carry it.

    The id is optional in the policy — but once present it is enforced against the id GitHub
    itself reported, because `owner/name` can be reassigned after a rename or transfer and a
    policy that only names the string can be inherited by a different repository wearing it.
    """
    pinned = policy.get("repositoryId")
    if pinned is None:
        return True, "the policy pins no numeric repository id"
    if observed_repository_id is None:
        return False, (f"the policy pins repository id {pinned} but no live observation "
                       f"reported the repository's numeric id to check it against")
    if str(observed_repository_id) != str(pinned):
        return False, (f"the policy pins repository id {pinned} but the observed repository "
                       f"has id {observed_repository_id}; this policy belongs to a different "
                       f"repository than the one being judged")
    return True, f"the observed repository id {observed_repository_id} matches the policy pin"


def window_valid(policy: Dict[str, Any], external_time: Optional[int],
                 external_time_source: str = "") -> Tuple[bool, str]:
    """notBefore <= externally-established-time <= notAfter, or no window at all."""
    not_before, not_after = policy.get("notBefore"), policy.get("notAfter")
    if not_before is None and not_after is None:
        return True, "the policy carries no validity window"
    if external_time is None:
        return False, ("the policy carries a validity window but no EXTERNALLY established "
                       "time exists to evaluate it against; the verifier's own clock is not "
                       "an external clock, so the window cannot be checked and the policy "
                       "cannot be relied on")
    if external_time_source and external_time_source not in EXTERNAL_TIME_SOURCES:
        return False, (f"the supplied time's source {external_time_source!r} is not an "
                       f"accepted external clock ({', '.join(EXTERNAL_TIME_SOURCES)})")
    if not_before is not None and external_time < not_before:
        return False, (f"the policy is not yet valid: external time {external_time} is "
                       f"before notBefore {not_before}")
    if not_after is not None and external_time > not_after:
        return False, (f"the policy has expired: external time {external_time} is after "
                       f"notAfter {not_after}")
    return True, (f"external time {external_time}"
                  + (f" ({external_time_source})" if external_time_source else "")
                  + " falls inside the policy's validity window")


def rollback_protected(policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Rollback protection is MANDATORY for independence.

    `policy.load` reports `rollbackChecked` honestly instead of raising when no state
    location is configured, because lower authority levels remain legitimate without it.
    What may NOT happen is an INDEPENDENTLY_ATTESTED award on top of an unprotected policy:
    a revoked verifier plus a replayed older policy would pass every other check.
    """
    if policy.get("rollbackChecked") is True:
        return True, (f"rollback state is maintained; highest seen version is "
                      f"{policy.get('highestSeenVersion')}")
    return False, ("policy rollback state is unavailable, unwritable or unauthenticated, so "
                   "a replayed older policy would not be detected. Lower authority levels "
                   "remain reachable; INDEPENDENTLY_ATTESTED is refused. Store rollback "
                   "state under the security-controlled verifier "
                   "(SHIPGATE_AUTHORITY_POLICY_STATE), outside the target repository.")


# =======================================================================================
# Deployment passage — evidence that THIS run went through the gate, not that a gate exists
# =======================================================================================
#
# Formerly `authority/deployment.py`; folded in because passage-judgement IS award
# enforcement — "one policy-enforcement function" includes the condition that distinguishes
# a configured gate from a used one. Everything below is a pure predicate: no I/O, no
# parsing, no network. The transport lives in live.py; the shape gate that keeps raw GitHub
# bytes from becoming a judged record without a real capture lives in SHAPES.json
# (gh.run.v1, gh.deployments.v1, gh.deployment.statuses.v1, gh.run.approvals.v1 - all
# BLOCKED in this release, each naming its unblock capture).

#: The deployment states GitHub reports that mean "this deployment completed successfully".
#: Exactly one value on purpose: "in_progress" and "queued" are not passage, and an unknown
#: state is refused, not mapped to the nearest good one.
SUCCESS_STATE = "success"


def judge_deployment(record: Optional[Dict[str, Any]], *, required_environment: str,
          expected_commit: str, expected_run_id: str,
          builder_ids: Tuple[str, ...] = ()) -> Tuple[bool, str, Dict[str, Any]]:
    """(ok, why, judged). The required conditions for independent release authority.

    `record` is the composed deployment-evidence record (see the shape below). Every check
    that fails is named; the first failure wins the message but the judged dict carries all
    of them, because an audit reads what was checked, not only what was decided.

        {
          "repositoryId":   the numeric repository id these records came from,
          "runId":          the workflow run the deployment belongs to,
          "runAttempt":     the attempt within that run,
          "runHeadSha":     the run's head commit,
          "runActorId":     who triggered the run (a builder-side principal),
          "deploymentId":   the deployment's numeric id,
          "environment":    the deployment's environment name,
          "deploymentSha":  the commit the deployment deployed,
          "statusState":    the deployment's terminal status state,
          "statusRunBound": True when the status record's own URLs name this run,
          "approvals":      [{"approverId": str, "approverLogin": str, "state": str}],
          "selfReviewPrevented": bool,   from the environment's protection rules
          "adminBypassDisabled": bool,   from the environment's protection rules
          "branchPolicySatisfied": bool, from the environment's protection rules
        }
    """
    checks: Dict[str, Any] = {}
    problems = []

    def check(name, ok, why):
        checks[name] = {"ok": bool(ok), "detail": why}
        if not ok:
            problems.append(why)

    if not isinstance(record, dict) or not record:
        return False, ("no deployment evidence exists for this run. A qualifying "
                       "environment CONFIGURATION is a description of a gate; independent "
                       "release authority needs evidence of passage — a deployment to the "
                       "required environment, succeeded, approved by someone the builder "
                       "is not, bound to this run and commit."), {"checks": {}}

    required = (required_environment or "").strip()
    check("environmentIsRequired",
          bool(required) and record.get("environment") == required,
          f"deployment environment {record.get('environment')!r} is the policy-required "
          f"{required!r}" if record.get("environment") == required and required else
          f"deployment environment {record.get('environment')!r} is not the policy-required "
          f"{required!r}")

    check("deploymentSucceeded",
          record.get("statusState") == SUCCESS_STATE,
          f"deployment status is {record.get('statusState')!r}"
          + ("" if record.get("statusState") == SUCCESS_STATE
             else f", not {SUCCESS_STATE!r}; a deployment that did not complete is not "
                  f"passage"))

    check("commitBound",
          bool(expected_commit)
          and str(record.get("deploymentSha", "")).lower() == expected_commit.lower()
          and str(record.get("runHeadSha", "")).lower() == expected_commit.lower(),
          f"deployment sha {str(record.get('deploymentSha'))[:12]!r} and run head "
          f"{str(record.get('runHeadSha'))[:12]!r} against decision commit "
          f"{expected_commit[:12]!r}")

    check("runBound",
          bool(expected_run_id) and str(record.get("runId")) == str(expected_run_id)
          and record.get("statusRunBound") is True,
          f"deployment/run binding: record names run {record.get('runId')!r} "
          f"(expected {expected_run_id!r}), status URLs name this run: "
          f"{record.get('statusRunBound')!r}")

    approvals = record.get("approvals")
    valid_approvals = [a for a in (approvals or ())
                       if isinstance(a, dict) and a.get("state") == "approved"
                       and a.get("approverId")]
    check("approvalPresent", bool(valid_approvals),
          f"{len(valid_approvals)} approved review(s) recorded"
          if valid_approvals else
          "no approval record exists; an environment that required reviewers but shows no "
          "approval did not gate this run")

    builder_side = {str(x) for x in builder_ids if x}
    actor = str(record.get("runActorId") or "")
    if actor:
        builder_side.add(actor)
    self_approved = [a for a in valid_approvals
                     if str(a.get("approverId")) in builder_side]
    check("notSelfApproved",
          bool(valid_approvals) and not self_approved,
          "every approver is distinct from the run's actor and the builder's principals"
          if valid_approvals and not self_approved else
          f"approver(s) {[a.get('approverLogin') or a.get('approverId') for a in self_approved]} "
          f"are the run's own actor or a builder-side principal; a self-approved "
          f"deployment introduces no second party")

    for name, label in (("selfReviewPrevented", "self-review prevention"),
                        ("adminBypassDisabled", "admin-bypass prohibition"),
                        ("branchPolicySatisfied", "the deployment branch policy")):
        check(name, record.get(name) is True,
              f"{label} is in force" if record.get(name) is True else
              f"{label} is not established ({record.get(name)!r}); an unknown protection "
              f"is an absent protection")

    ok = not problems
    why = ("this run's release demonstrably passed through the required protected "
           "environment: deployed, succeeded, approved by a distinct party, bound to this "
           "run and commit" if ok else "; ".join(problems[:4]))
    return ok, why, {"checks": checks,
                     "deploymentId": record.get("deploymentId"),
                     "environment": record.get("environment"),
                     "approvers": [a.get("approverLogin") or a.get("approverId")
                                   for a in valid_approvals]}


def enforce_award(policy: Optional[Dict[str, Any]], *,
                  verifier_identity: str = "",
                  builder_identity: str = "",
                  observed_environment: Optional[str] = None,
                  observed_repository_id: Optional[Any] = None,
                  external_time: Optional[int] = None,
                  external_time_source: str = "",
                  deployment: Optional[Dict[str, Any]] = None,
                  expected_commit: str = "",
                  expected_run_id: str = "",
                  builder_ids: Any = (),
                  observation_mode: str = "") -> Dict[str, Any]:
    """Run EVERY policy check that gates independence. Returns a verdict, never raises.

    The result's `authorized` is True only when every check passed. `reasonCodes` carries one
    AUT_* code per failed check, most fundamental first. `checks` records each check's own
    (ok, detail) so an audit reads what was enforced, not just what was decided.
    """
    if not isinstance(policy, dict) or not policy:
        return {
            "authorized": False,
            "policyRollbackProtected": False,
            "reasonCodes": (R.AUT_PRINCIPAL_NOT_DISTINCT,),
            "checks": {},
            "detail": ("no verified external policy is attached to this observation, so "
                       "nothing external authorises any award of independence"),
        }

    checks: Dict[str, Any] = {}
    codes = []

    ok, why = verifier_authorized(policy, verifier_identity)
    checks["verifierAuthorized"] = {"ok": ok, "detail": why}
    if not ok:
        codes.append(R.AUT_PRINCIPAL_NOT_DISTINCT)

    ok, why = builder_authorized(policy, builder_identity)
    checks["builderAuthorized"] = {"ok": ok, "detail": why}
    if not ok:
        codes.append(R.AUT_BUILDER_NOT_AUTHORIZED)

    ok, why = environment_matches(policy, observed_environment)
    checks["environmentMatches"] = {"ok": ok, "detail": why}
    if not ok:
        codes.append(R.AUT_ENVIRONMENT_UNSUPPORTED)

    ok, why = repository_id_matches(policy, observed_repository_id)
    checks["repositoryIdMatches"] = {"ok": ok, "detail": why}
    if not ok:
        codes.append(R.AUT_BINDING_MISMATCH)

    ok, why = window_valid(policy, external_time, external_time_source)
    checks["windowValid"] = {"ok": ok, "detail": why}
    if not ok:
        codes.append(R.AUT_POLICY_WINDOW_INVALID)

    rollback_ok, why = rollback_protected(policy)
    checks["rollbackProtected"] = {"ok": rollback_ok, "detail": why}
    if not rollback_ok:
        codes.append(R.AUT_POLICY_ROLLBACK_UNPROTECTED)

    # PASSAGE, NOT EXISTENCE. A qualifying environment configuration describes a gate;
    # independence needs evidence that THIS run's release went through it. The judgement
    # itself lives in `deployment.judge` (pure, field-by-field); a refusal here carries
    # AUT_DEPLOYMENT_NOT_BOUND and, like every other failed check, demotes the award.
    # THE STRONGER TWO-PHASE MODE IS REQUIRED for the strongest persisted result. A
    # single-phase live observation signs only the release identity (decision, commit,
    # run); the response bodies ride along unsigned, on trust that the same process made
    # them. That is fine for diagnostics and for lower tiers, and it is not fine for a
    # persisted INDEPENDENTLY_ATTESTED: the persisted evidence must carry a signature over
    # WHAT WAS SEEN, which only the signed-replay (observation-challenge) mode provides.
    ok = observation_mode == "signed-replay"
    checks["twoPhaseObservation"] = {
        "ok": ok,
        "detail": ("the verifier's signature covers the observed response bodies "
                   "(signed-replay mode)" if ok else
                   f"observation mode is {observation_mode or 'unknown'!r}; the strongest "
                   f"persisted authority requires the two-phase signed observation, whose "
                   f"signature covers the exact bytes GitHub returned. Record phase 1 with "
                   f"`gate.py observe`, sign the challenge, and attest with "
                   f"verifier.observation set.")}
    if not ok:
        codes.append(R.AUT_PRINCIPAL_NOT_DISTINCT)

    dep_ok, why, judged = judge_deployment(
        deployment,
        required_environment=str(policy.get("requiredEnvironment") or ""),
        expected_commit=expected_commit,
        expected_run_id=expected_run_id,
        builder_ids=tuple(str(x) for x in (builder_ids or ()) if x))
    checks["deploymentBound"] = {"ok": dep_ok, "detail": why, "judged": judged}
    if not dep_ok:
        codes.append(R.AUT_DEPLOYMENT_NOT_BOUND)

    authorized = not codes
    return {
        "authorized": authorized,
        "policyRollbackProtected": rollback_ok,
        "reasonCodes": tuple(dict.fromkeys(codes)),
        "checks": checks,
        "detail": ("every policy constraint is satisfied" if authorized else
                   "; ".join(c["detail"] for c in checks.values() if not c["ok"])),
    }


def describe() -> str:
    return "\n".join([
        "POLICY ENFORCEMENT — one function, every field.",
        "",
        "  authorizedVerifiers  exact normalised membership; a key: identity only when the",
        "                       signed policy itself pins that exact key",
        "  authorizedBuilders   the VERIFIED builder identity (certificate SAN), never a",
        "                       config value; no verified builder means no independence",
        "  requiredEnvironment  must equal the OBSERVED deployment environment",
        "  repositoryId         when pinned, must equal the id GitHub itself reported",
        "  notBefore/notAfter   judged against externally established time only; a window",
        "                       with no external clock is a refusal",
        "  rollback             mandatory for independence; unprotected state caps the award",
        "",
        "  deployment           PASSAGE through the required environment: deployed,",
        "                       succeeded, approved by a distinct party, bound to this run",
        "                       and commit, under self-review/bypass/branch protections",
        "",
        "  A failed check demotes the award. It never becomes a warning.",
    ])


__all__ = [
    "EXTERNAL_TIME_SOURCES", "SUCCESS_STATE", "builder_authorized", "enforce_award",
    "environment_matches", "judge_deployment", "normalise_identity",
    "repository_id_matches", "rollback_protected", "verifier_authorized", "window_valid",
]
