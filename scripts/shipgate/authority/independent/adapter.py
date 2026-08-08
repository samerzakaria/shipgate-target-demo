"""Independent attestation adapter — ceiling `INDEPENDENTLY_ATTESTED`.

Everything the CI adapter requires, PLUS proof that a principal the builder cannot
impersonate had to act. In this release that principal is a GitHub environment with a
`required_reviewers` protection rule, a deployment branch policy, and `can_admins_bypass`
false — checked through `gh api`, i.e. GitHub's answer, not the repository's own files.

The captured environment is the opposite of that:

    {"protection_rules": [], "deployment_branch_policy": null, "can_admins_bypass": true}

so this adapter refuses it with `AUT_PRINCIPAL_NOT_DISTINCT`. An environment anyone can
create and anyone can deploy to introduces no second principal — a builder that could count
it would simply be marking its own homework in a different colour.

The qualifying (protected) shape has never been captured either — GitHub Free private repos
cannot set protection rules (HTTP 422) — so it is refused with `AUT_OUTPUT_SHAPE_UNKNOWN`.
Both doors are therefore shut, deliberately and visibly: this adapter cannot emit
`INDEPENDENTLY_ATTESTED` in this release, and it says which capture would change that.

One more thing this adapter does NOT do: it does not accept an independence claim from the
run that produced the decision. Independence is a property of the verifying environment,
which is why `assets/ci/shipgate-independent.yml` runs the verifier as a SEPARATE job, in a
protected environment, with the builder's token nowhere in scope.
"""
from ...models.decision import ProvenanceStatus
from ..adapter_base import AuthorityAdapter
from ..verifiers import (
    CosignBundleVerifier,
    GhAttestationVerifier,
    GithubEnvironmentPrincipalVerifier,
    GithubOidcIdentityVerifier,
    RekorTransparencyVerifier,
)


class IndependentAuthorityAdapter(AuthorityAdapter):
    """Emits at most `ProvenanceStatus.INDEPENDENTLY_ATTESTED`."""

    name = "shipgate-authority-independent"
    version = "shipgate-authority-independent/4.2.4"
    mode = "independent"
    ceiling = ProvenanceStatus.INDEPENDENTLY_ATTESTED
    verifier_classes = (
        GithubOidcIdentityVerifier,          # identity
        CosignBundleVerifier,                # binding
        RekorTransparencyVerifier,           # freshness
        GhAttestationVerifier,               # identity+binding+freshness — GitHub's verifier
        GithubEnvironmentPrincipalVerifier,  # principal — the separate trust boundary
    )

    def ready_reason(self):
        from ...models import reasons as R
        return R.AUT_INDEPENDENTLY_ATTESTED


__all__ = ["IndependentAuthorityAdapter"]
