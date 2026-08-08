"""Stable reason codes.

A reason code is a CONSUMER CONTRACT: it may be added, but never renamed, renumbered, or
given a new meaning within a decision schema version. Human text may change freely; the
code may not. `tests/unit/test_reason_codes.py` pins the whole frozen set.

Namespaces
  SEM_*   semantic evaluation (Axis B) — why the run passed or failed on the merits
  EVD_*   evidence handling — missing / stale / malformed / contradictory / mismatched
  EXE_*   execution containment
  PRF_*   profile & requirement resolution
  AUT_*   provenance / authority (Axis A) — emitted ONLY by authority adapters
  COV_*   phase coverage — SELF-ATTESTED, and structurally incapable of raising a status
  OPS_*   operational: break-glass, mode, infrastructure
"""

# --- Axis B: semantics -------------------------------------------------------------
SEM_ALL_REQUIRED_CHECKS_PASSED = "SEM_ALL_REQUIRED_CHECKS_PASSED"
SEM_REQUIRED_CHECK_FAILED = "SEM_REQUIRED_CHECK_FAILED"
SEM_REQUIRED_CHECK_NOT_RUN = "SEM_REQUIRED_CHECK_NOT_RUN"
SEM_THRESHOLD_NOT_MET = "SEM_THRESHOLD_NOT_MET"
SEM_THRESHOLD_UNMEASURED = "SEM_THRESHOLD_UNMEASURED"
SEM_SHOWSTOPPER_OPEN = "SEM_SHOWSTOPPER_OPEN"
SEM_BLOCKER_OPEN = "SEM_BLOCKER_OPEN"
SEM_CUJ_NOT_EVIDENCED = "SEM_CUJ_NOT_EVIDENCED"
SEM_CUJ_DOWNGRADE_REFUSED = "SEM_CUJ_DOWNGRADE_REFUSED"
SEM_HELDOUT_NOT_EVALUATED = "SEM_HELDOUT_NOT_EVALUATED"
SEM_HELDOUT_FAILED = "SEM_HELDOUT_FAILED"
SEM_HELDOUT_EMPTY = "SEM_HELDOUT_EMPTY"
SEM_MUTATION_BELOW_THRESHOLD = "SEM_MUTATION_BELOW_THRESHOLD"
SEM_UNDETECTED_FAULT = "SEM_UNDETECTED_FAULT"
SEM_FAIL_FIRST_NOT_ADMITTED = "SEM_FAIL_FIRST_NOT_ADMITTED"
SEM_WIRING_GAP = "SEM_WIRING_GAP"
SEM_RUNTIME_NOT_SERVED = "SEM_RUNTIME_NOT_SERVED"
SEM_SPEC_UNSEALED = "SEM_SPEC_UNSEALED"
SEM_SPEC_DRIFT_UNLOGGED = "SEM_SPEC_DRIFT_UNLOGGED"
SEM_TEST_SEAL_BROKEN = "SEM_TEST_SEAL_BROKEN"
SEM_TEST_SEAL_EMPTY = "SEM_TEST_SEAL_EMPTY"
SEM_A11Y_SERIOUS = "SEM_A11Y_SERIOUS"
SEM_SECURITY_SERIOUS = "SEM_SECURITY_SERIOUS"
SEM_PERFORMANCE_BELOW_BUDGET = "SEM_PERFORMANCE_BELOW_BUDGET"
SEM_ROLE_SEPARATION_VIOLATED = "SEM_ROLE_SEPARATION_VIOLATED"
SEM_CONVERGENCE_NOT_REACHED = "SEM_CONVERGENCE_NOT_REACHED"
SEM_ADVERSARIAL_AUTHZ_BYPASS = "SEM_ADVERSARIAL_AUTHZ_BYPASS"
SEM_ADVERSARIAL_UNHANDLED_ERROR = "SEM_ADVERSARIAL_UNHANDLED_ERROR"
SEM_ADVERSARIAL_PROBE_NOT_ADMITTED = "SEM_ADVERSARIAL_PROBE_NOT_ADMITTED"
SEM_REQUIREMENTS_UNLINKED = "SEM_REQUIREMENTS_UNLINKED"
SEM_REQUIREMENTS_UNDER_EXTRACTED = "SEM_REQUIREMENTS_UNDER_EXTRACTED"
SEM_DESIGN_NONCONFORMANT = "SEM_DESIGN_NONCONFORMANT"
SEM_CROSS_SURFACE_INCONSISTENT = "SEM_CROSS_SURFACE_INCONSISTENT"
SEM_PHASE_CHECKER_NOT_ADMITTED = "SEM_PHASE_CHECKER_NOT_ADMITTED"

# --- Evidence handling (all fail-closed) --------------------------------------------
EVD_REQUIRED_MISSING = "EVD_REQUIRED_MISSING"
EVD_STALE = "EVD_STALE"
EVD_MALFORMED = "EVD_MALFORMED"
EVD_CONTRADICTORY = "EVD_CONTRADICTORY"
EVD_INCOMPLETE = "EVD_INCOMPLETE"
EVD_RUN_MISMATCH = "EVD_RUN_MISMATCH"
EVD_COMMIT_MISMATCH = "EVD_COMMIT_MISMATCH"
EVD_ARTIFACT_MISMATCH = "EVD_ARTIFACT_MISMATCH"
EVD_PROFILE_MISMATCH = "EVD_PROFILE_MISMATCH"
EVD_DIGEST_MISMATCH = "EVD_DIGEST_MISMATCH"
EVD_COLLECTOR_ERROR = "EVD_COLLECTOR_ERROR"
EVD_UNSUPPORTED_SHAPE = "EVD_UNSUPPORTED_SHAPE"

# --- Execution containment -----------------------------------------------------------
EXE_CONTAINMENT_REQUIRED_UNAVAILABLE = "EXE_CONTAINMENT_REQUIRED_UNAVAILABLE"
EXE_CONTAINMENT_REFUSED = "EXE_CONTAINMENT_REFUSED"
EXE_CONTAINMENT_DEGRADED = "EXE_CONTAINMENT_DEGRADED"
EXE_TIMEOUT = "EXE_TIMEOUT"
EXE_OUTPUT_LIMIT_EXCEEDED = "EXE_OUTPUT_LIMIT_EXCEEDED"
EXE_ADAPTER_BYPASS_DETECTED = "EXE_ADAPTER_BYPASS_DETECTED"

# --- Profiles / requirements ---------------------------------------------------------
PRF_RESOLVED = "PRF_RESOLVED"
PRF_ESCALATED_RISK = "PRF_ESCALATED_RISK"
PRF_ESCALATED_PROTECTED_AREA = "PRF_ESCALATED_PROTECTED_AREA"
PRF_ESCALATED_UNCERTAINTY = "PRF_ESCALATED_UNCERTAINTY"
PRF_ESCALATED_POLICY = "PRF_ESCALATED_POLICY"
PRF_DOWNGRADE_REFUSED = "PRF_DOWNGRADE_REFUSED"
PRF_UNKNOWN_PROFILE = "PRF_UNKNOWN_PROFILE"
PRF_DIGEST_MISMATCH = "PRF_DIGEST_MISMATCH"

# --- Axis A: provenance / authority (authority adapters only) -------------------------
AUT_KIT_ABSENT = "AUT_KIT_ABSENT"
AUT_NOT_CONFIGURED = "AUT_NOT_CONFIGURED"
AUT_ENVIRONMENT_UNSUPPORTED = "AUT_ENVIRONMENT_UNSUPPORTED"
AUT_TOOL_MISSING = "AUT_TOOL_MISSING"
AUT_TOOL_VERSION_UNSUPPORTED = "AUT_TOOL_VERSION_UNSUPPORTED"
AUT_OUTPUT_SHAPE_UNKNOWN = "AUT_OUTPUT_SHAPE_UNKNOWN"
AUT_IDENTITY_NOT_ESTABLISHED = "AUT_IDENTITY_NOT_ESTABLISHED"
AUT_IDENTITY_NOT_PERMITTED = "AUT_IDENTITY_NOT_PERMITTED"
AUT_BINDING_MISMATCH = "AUT_BINDING_MISMATCH"
#: A recorded observation's body does not match the digest the verifier's signature covers.
#: Distinct from AUT_BINDING_MISMATCH on purpose: a reviewer must be able to tell "the
#: recording was edited" from "this evidence is about a different release", and a test must
#: be able to assert the digest caught a forgery rather than the policy layer happening to.
AUT_BODY_DIGEST_MISMATCH = "AUT_BODY_DIGEST_MISMATCH"
AUT_FRESHNESS_EXPIRED = "AUT_FRESHNESS_EXPIRED"
AUT_SIGNATURE_INVALID = "AUT_SIGNATURE_INVALID"
AUT_PRINCIPAL_NOT_DISTINCT = "AUT_PRINCIPAL_NOT_DISTINCT"
AUT_SEMANTIC_NOT_PASSED = "AUT_SEMANTIC_NOT_PASSED"
#: A provenance record was found beside (or inside) a decision and was NOT re-verified.
#:
#: This code exists because of a P0 found in external audit: `gate.py verdict` used to read
#: `provenanceStatus` straight out of an `attestation.json` sidecar — or out of an
#: `attestation` key appended to the envelope, which the digest does not cover — and hand it
#: back as the run's provenance. Two fields in a file anyone could write were enough to turn
#: VERIFIED into INDEPENDENTLY_ATTESTED, with no signature, no identity, no evidence and no
#: adapter. A status on disk is a CLAIM. Provenance is now re-established or it is absent,
#: and this code is what "absent, and here is why" looks like.
AUT_RECORD_NOT_REVERIFIED = "AUT_RECORD_NOT_REVERIFIED"
#: v4.2 policy enforcement. Rollback protection is MANDATORY for independence: a policy whose
#: highest-seen version is not being remembered somewhere the target cannot write can be
#: replayed after a revocation, and every other check passes because the replayed document is
#: genuinely valid and genuinely signed. Without rollback state the award is capped below
#: INDEPENDENTLY_ATTESTED — a refusal, not a warning attached to a success.
AUT_POLICY_ROLLBACK_UNPROTECTED = "AUT_POLICY_ROLLBACK_UNPROTECTED"
#: The policy carries a validity window (notBefore/notAfter) and either the externally
#: established time falls outside it, or no externally established time exists at all. Local
#: wall-clock is never an external clock: the verifier controls it, so "the policy is current"
#: would otherwise be self-attested. Covers not-yet-valid, expired, and missing-external-time.
AUT_POLICY_WINDOW_INVALID = "AUT_POLICY_WINDOW_INVALID"
#: The externally verified BUILDER identity is not in the policy's authorizedBuilders — or no
#: externally verified builder identity exists to check. Distinct from
#: AUT_IDENTITY_NOT_PERMITTED (an issuer/trust-root problem) and from
#: AUT_PRINCIPAL_NOT_DISTINCT (a verifier-side problem): this one means the build itself came
#: from a workflow the policy does not name, and independence is refused for that reason.
AUT_BUILDER_NOT_AUTHORIZED = "AUT_BUILDER_NOT_AUTHORIZED"
#: Independent release authority requires evidence that THIS run actually passed through the
#: policy-required protected environment — a deployment, its success status, and an approval
#: by someone who is not the run's own actor, all bound to this run and commit. A qualifying
#: environment CONFIGURATION alone is a description of a gate, not evidence that anyone went
#: through it. This code is the refusal when that evidence is absent, unbound, self-approved,
#: bypassed, or unverifiable.
AUT_DEPLOYMENT_NOT_BOUND = "AUT_DEPLOYMENT_NOT_BOUND"
AUT_CI_ATTESTED = "AUT_CI_ATTESTED"
AUT_INDEPENDENTLY_ATTESTED = "AUT_INDEPENDENTLY_ATTESTED"

# --- Phase coverage (SELF-ATTESTED; may only subtract) ---------------------------------
#
# These describe what the OPERATING AGENT says it did, which is the least trustworthy input
# in the system. They exist so that "the automated evidence passed" is never silently read
# as "everything in the procedure was done". Three properties are structural, not stylistic:
#
#   * None of them is in SEMANTIC_FAILING, so a coverage code can never fail a run.
#   * None of them is in AUTHORITY_EMITTABLE, so an adapter cannot author one.
#   * There is no COV_* code meaning "coverage complete". A positive self-report cannot be
#     the reason a caveat disappears — only collected evidence removes a caveat, so the
#     vocabulary simply has no word for the unsafe direction.
COV_PARTIAL_SELF_DECLARED = "COV_PARTIAL_SELF_DECLARED"
COV_PHASE_NOT_RUN = "COV_PHASE_NOT_RUN"
COV_PHASE_CLAIM_UNCORROBORATED = "COV_PHASE_CLAIM_UNCORROBORATED"
COV_ADVERSARIAL_NOT_COLLECTED = "COV_ADVERSARIAL_NOT_COLLECTED"

# --- Operational ----------------------------------------------------------------------
OPS_BREAK_GLASS = "OPS_BREAK_GLASS"
OPS_MODE_ADVISORY = "OPS_MODE_ADVISORY"
OPS_MODE_OBSERVE = "OPS_MODE_OBSERVE"
OPS_MODE_ENFORCE = "OPS_MODE_ENFORCE"
OPS_INFRASTRUCTURE_FAILURE = "OPS_INFRASTRUCTURE_FAILURE"
OPS_PLATFORM_UNSUPPORTED = "OPS_PLATFORM_UNSUPPORTED"


def _collect():
    g = globals()
    return frozenset(
        v for k, v in list(g.items())
        if k.isupper() and isinstance(v, str) and k == v
    )


ALL_REASON_CODES = _collect()

#: Codes an authority adapter is permitted to emit. Anything else from an adapter is a
#: contract violation — the adapter must not be able to author a semantic reason.
AUTHORITY_EMITTABLE = frozenset(c for c in ALL_REASON_CODES if c.startswith("AUT_"))

#: Codes carried by the self-attested coverage block. Never failing, never authority-emittable.
COVERAGE_CODES = frozenset(c for c in ALL_REASON_CODES if c.startswith("COV_"))

#: Codes that, when present in a decision, force semantic_status == FAILED.
SEMANTIC_FAILING = frozenset(
    c for c in ALL_REASON_CODES
    if (c.startswith("SEM_") and c != SEM_ALL_REQUIRED_CHECKS_PASSED)
    or c.startswith("EVD_")
    or c in (EXE_CONTAINMENT_REQUIRED_UNAVAILABLE, EXE_CONTAINMENT_REFUSED,
             EXE_ADAPTER_BYPASS_DETECTED, PRF_UNKNOWN_PROFILE, PRF_DIGEST_MISMATCH,
             OPS_PLATFORM_UNSUPPORTED)
)


def is_valid(code):
    return code in ALL_REASON_CODES


def require_valid(code):
    if code not in ALL_REASON_CODES:
        raise ValueError(f"unknown reason code: {code!r}")
    return code
