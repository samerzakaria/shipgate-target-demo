"""The BOUNDED OPTIONAL AUTHORITY KIT — Axis A, and nothing else.

This whole directory is optional. Delete it and the VERIFIED workflow is unchanged: nothing
outside `shipgate/authority/` imports it (`shipgate.authority_status()` probes with
`importlib.util.find_spec`), and a bare `Decision` already reports
`ProvenanceStatus.NONE`. The semantic answer does not depend on anything in here.

What an adapter can do to a decision: NOTHING. It reads the decision's digest and returns an
`Attestation` carrying that digest, some evidence about it, and AUT_ reason codes. It cannot
alter, repair, replace, downgrade or bypass a decision — `Decision` is frozen,
`AttestedDecision` re-checks the digest, and `derive_outcome` collapses every provenance
value to FAILED when the semantics failed.

Dependencies: `shipgate.models`, `shipgate.util`, `shipgate.execadapter`, stdlib. Nothing
else from shipgate, and no third-party package. Importing this module runs no tool, touches
no network, and works on a machine with neither cosign nor rekor-cli nor gh installed.

Scope, closed: cosign (verify-blob + bundle), Rekor (REST entry + rekor-cli), GitHub Actions
OIDC claims, and the `gh` API repository/environment shapes. No other provider, format,
principal type, policy system or verification stage. v3.8's custom trust-policy engine,
signer, release manifest and standalone verifier are QUARANTINED, not extended.

Entry points:
    availability()          -> {"present", "configured", "reason", "detail"}
    attest(decision, config) -> models.decision.Attestation
"""
from ..models import reasons as R
from ..models.decision import Attestation, ProvenanceStatus
from . import contracts, fixtures, parsers, shapes, verifiers
from .adapter_base import AuthorityAdapter
from .ci.adapter import CiAuthorityAdapter
from .contracts import AuthorityConfig, AuthorityConfigError, VerifierResult, evaluate
from .independent.adapter import IndependentAuthorityAdapter

KIT_VERSION = "shipgate-authority/4.2.2"

#: mode -> adapter. The only two adapters that exist; the scope is closed.
ADAPTERS = {
    "ci": CiAuthorityAdapter,
    "independent": IndependentAuthorityAdapter,
}


def availability(config=None):
    """Is the authority kit present, and is it configured to do anything?

    `present` is True by construction — you are reading this because the package imported.
    `configured` is about the OPERATOR's environment, and it is False by default: installing
    the skill does not configure, certify or vouch for any external environment.

    Never raises. A broken config is reported, not thrown, because a caller asking "can you
    attest?" must always get an answer.
    """
    detail_parts = []
    reg = shapes.registry()
    blocked = reg.blocked_ids()
    validated = reg.validated_ids()
    if reg.load_error:
        detail_parts.append(f"shape registry: {reg.load_error}")
    detail_parts.append(
        f"{len(validated)} output shapes VALIDATED against real captures; "
        f"{len(blocked)} BLOCKED" + (f" ({', '.join(blocked)})" if blocked else ""))
    # The one remaining blocked shape has a REASON with a receipt. Naming the evidence file
    # here is the difference between "we could not capture it" and "here is what happened when
    # we tried".
    for shape_id in blocked:
        entry = reg.get(shape_id)
        if entry is not None and entry.blocked_evidence:
            detail_parts.append(
                f"{shape_id} is blocked with digest-pinned evidence of why "
                f"({entry.blocked_evidence.get('captureFile')}: keyless signing needs an OIDC "
                "token, and without one cosign falls back to an interactive device-code flow, "
                "so no unattended capture is possible)"
                + (f" [{entry.blocked_evidence_problem}]"
                   if entry.blocked_evidence_problem else ""))
    # A VALIDATED shape means "we have seen this shape", NOT "the identity inside it binds
    # to anything". Saying so here stops the count above from being read as more than it is.
    bound = [s for s in validated if reg.get(s).binding_validated]
    detail_parts.append(
        f"{len(bound)} of {len(validated)} validated shapes also prove an identity BINDING"
        + ("" if bound else " — the capture corpus is sanitized (the identity-bearing keyless "
                            "bundle) or identity-free (both KEYED bundles sign a blob and "
                            "carry no certificate), so binding is proved by runtime checks "
                            "(cosign.check_binding, cosign.check_certificate_identity), never "
                            "by a fixture"))
    # VERSION TIERS. Four distinct provenance situations, not one. Reporting the counts here
    # keeps "which cosign made this?" from silently collapsing into a single averaged claim,
    # and makes a null version constraint visible instead of implied.
    tiers = reg.version_tiers()
    detail_parts.append(
        "producing-tool provenance: "
        + "; ".join(f"{name} x{len(ids)}" for name, ids in sorted(tiers.items()))
        + ". OBSERVED-CAPTURE = the tool printed its own version (cosign v3.1.2 and v3.1.3, "
          "both in the corpus); OPERATOR-ASSERTED-CONFIRMED = stated by the operator and "
          "confirmed by the capture author (rekor-cli v1.5.3, gh 2.65.0 of 2025-01-06); "
          "RUNNER-RESOLVED = installed by sigstore/cosign-installer@v3 or the runner's ambient "
          "gh on a GitHub-hosted runner, mechanisms that pin no version, so the version "
          "constraint is null and NOT a guessed number; SERVER-API = a Rekor api/v1 document "
          "with no client tool to version. No shape reports UNSTATED"
        + ("" if not reg.retired_version_states()
           else " EXCEPT " + ", ".join(reg.retired_version_states())))
    # Freshness is the one property a shipped capture cannot hold, and saying so here stops
    # "we have a fresh bound Rekor entry" from being read as "this kit ships fresh evidence".
    detail_parts.append(
        "the corpus contains a Rekor REST entry BOUND to a captured bundle "
        "(logIndex 2354787700, byte-identical logged body), which is what lets the freshness "
        "verifier be exercised against bound evidence — but that entry is PERISHABLE and is "
        "stale against a real clock within the hour, and it belongs to a KEYED bundle that "
        "carries no identity. No shipped capture can produce a live CI_ATTESTED")

    if config is None:
        detail_parts.append(
            "no authority configuration supplied — the VERIFIED workflow needs none, and "
            "installing this skill certifies no external environment")
        return {"present": True, "configured": False, "reason": R.AUT_NOT_CONFIGURED,
                "detail": " | ".join(detail_parts)}

    try:
        cfg = AuthorityConfig.coerce(config)
    except AuthorityConfigError as exc:
        detail_parts.append(f"config rejected: {exc}")
        return {"present": True, "configured": False, "reason": R.AUT_NOT_CONFIGURED,
                "detail": " | ".join(detail_parts)}

    adapter_cls = ADAPTERS.get(cfg.mode)
    if adapter_cls is None:
        detail_parts.append(f"no adapter for mode {cfg.mode!r}")
        return {"present": True, "configured": False,
                "reason": R.AUT_ENVIRONMENT_UNSUPPORTED, "detail": " | ".join(detail_parts)}

    configured, reason, detail = adapter_cls(cfg).availability()
    if detail:
        detail_parts.append(detail)
    detail_parts.append(f"adapter={adapter_cls.name} ceiling={adapter_cls.ceiling.value}")
    return {"present": True, "configured": bool(configured), "reason": reason,
            "detail": " | ".join(detail_parts)}


def attest(decision, config=None):
    """The single entry point `gate.py` calls. Always returns an `Attestation`.

    A refusal is an `Attestation` with `ProvenanceStatus.UNAVAILABLE` and the AUT_ codes that
    explain it — never an exception, never None, and never a mutated decision. The caller
    decides what to do with it; `AttestedDecision` will independently refuse to pair a
    CI_ATTESTED/INDEPENDENTLY_ATTESTED attestation with a decision that did not pass.
    """
    digest = ""
    try:
        digest = decision.digest()
    except (AttributeError, TypeError) as exc:
        return Attestation(
            provenance_status=ProvenanceStatus.UNAVAILABLE, decision_digest="",
            verifier=KIT_VERSION, verifier_version=KIT_VERSION,
            reason_codes=(R.AUT_ENVIRONMENT_UNSUPPORTED,),
            detail=f"not an attestable Decision: {exc}")

    if config is None:
        return Attestation(
            provenance_status=ProvenanceStatus.UNAVAILABLE, decision_digest=digest,
            verifier=KIT_VERSION, verifier_version=KIT_VERSION,
            reason_codes=(R.AUT_NOT_CONFIGURED,),
            detail="authority was not configured; the decision stands on its semantics alone")

    try:
        cfg = AuthorityConfig.coerce(config)
    except AuthorityConfigError as exc:
        return Attestation(
            provenance_status=ProvenanceStatus.UNAVAILABLE, decision_digest=digest,
            verifier=KIT_VERSION, verifier_version=KIT_VERSION,
            reason_codes=(R.AUT_NOT_CONFIGURED,),
            detail=f"authority config rejected: {exc}")

    adapter_cls = ADAPTERS.get(cfg.mode)
    if adapter_cls is None:
        return Attestation(
            provenance_status=ProvenanceStatus.UNAVAILABLE, decision_digest=digest,
            verifier=KIT_VERSION, verifier_version=KIT_VERSION,
            reason_codes=(R.AUT_ENVIRONMENT_UNSUPPORTED,),
            detail=f"no authority adapter for mode {cfg.mode!r}")

    return adapter_cls(cfg).attest(decision)


def shape_matrix():
    """The VALIDATED / BLOCKED matrix, for reporting and for tests."""
    return shapes.registry().matrix()


def rule_table():
    """The verifier-facts -> ProvenanceStatus rules, as data."""
    return contracts.rule_table_json()


__all__ = [
    "ADAPTERS", "Attestation", "AuthorityAdapter", "AuthorityConfig", "AuthorityConfigError",
    "CiAuthorityAdapter", "IndependentAuthorityAdapter", "KIT_VERSION", "ProvenanceStatus",
    "VerifierResult", "attest", "availability", "contracts", "evaluate", "fixtures",
    "parsers", "rule_table", "shape_matrix", "shapes", "verifiers",
]
