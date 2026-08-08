"""CI attestation adapter — ceiling `CI_ATTESTED`, and not one step higher.

What CI_ATTESTED means, precisely: a CI system whose identity was asserted by an external
issuer produced a signature over THIS decision's digest, and that signature is in a public
transparency log, recently. It does NOT mean anyone independent looked at anything. The
builder and the attester are the same principal; that is why this adapter's ceiling is
`CI_ATTESTED` and why no combination of evidence it can gather will produce
`INDEPENDENTLY_ATTESTED` — `contracts.evaluate` is called with the ceiling and skips the
stronger rule entirely.

Refusals, in the order they fire:
  * semantic status is not PASSED, or the decision contradicts itself   AUT_SEMANTIC_NOT_PASSED
  * no config, or a config with an unknown key                          AUT_NOT_CONFIGURED
  * config written for the independent adapter                          AUT_ENVIRONMENT_UNSUPPORTED
  * configured evidence file absent                                     AUT_TOOL_MISSING
  * cosign/rekor/gh version outside the validated range, or absent      AUT_TOOL_VERSION_UNSUPPORTED
  * output shape never captured (keyless bundle, OIDC claims)           AUT_OUTPUT_SHAPE_UNKNOWN
  * cosign said the signature is bad                                    AUT_SIGNATURE_INVALID
  * the signature is over some other digest                             AUT_BINDING_MISMATCH
  * the log entry is stale, or dated in the future                      AUT_FRESHNESS_EXPIRED
  * identity is not established (ALWAYS, in this release)               AUT_IDENTITY_NOT_ESTABLISHED

That last one is unconditional today: establishing identity needs either a verified OIDC
claim set or a Fulcio-backed keyless cosign bundle, and neither shape has a real capture. So
this adapter cannot currently emit CI_ATTESTED at all. That is a deliberate, documented,
fail-closed state — see schemas/SHAPES.json and assets/ci/DEPLOYMENT.md — not a bug, and the
attestation it returns says exactly which shape is missing.
"""
from ...models.decision import ProvenanceStatus
from ..adapter_base import AuthorityAdapter
from ..verifiers import (
    CosignBundleVerifier,
    GhAttestationVerifier,
    GithubOidcIdentityVerifier,
    RekorTransparencyVerifier,
)


class CiAuthorityAdapter(AuthorityAdapter):
    """Emits at most `ProvenanceStatus.CI_ATTESTED`.

    v4.2: two evidence paths produce the same fact contracts and either can establish them —
    GitHub artifact attestation (GitHub's own verifier, actually run; the preferred path on
    GitHub) and cosign/Sigstore (provider-neutral, fully offline). When both are configured
    both run, and the merge keeps the first established fact per slot; a contradiction
    between them surfaces as a binding mismatch in whichever verifier saw it.
    """

    name = "shipgate-authority-ci"
    version = "shipgate-authority-ci/4.2.2"
    mode = "ci"
    ceiling = ProvenanceStatus.CI_ATTESTED
    verifier_classes = (
        GithubOidcIdentityVerifier,   # identity  — from the external issuer, never a CLI arg
        CosignBundleVerifier,         # binding   — to THIS decision digest
        RekorTransparencyVerifier,    # freshness — the log's integratedTime
        GhAttestationVerifier,        # identity+binding+freshness — GitHub's own verifier
    )


__all__ = ["CiAuthorityAdapter"]
