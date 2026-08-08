"""The authority contract: what a verifier may say, and what that entitles a decision to.

Three things live here and nothing else:

  `VerifierResult`   what one verifier concluded. A verifier reports FACTS
                     (identity / binding / freshness / principal) and AUT_* reason codes.
                     It does not get a vote on the provenance status.
  `AuthorityConfig`  strict, JSON-loaded configuration. Unknown keys are a hard error —
                     a typo must not silently disable a requirement.
  `RULES` / `evaluate`  the single table that turns verifier facts into a `ProvenanceStatus`.

The rule table is deliberately the only place a `ProvenanceStatus` above UNAVAILABLE can be
produced in this kit. Adapters gather facts; they do not grade themselves.

  CI_ATTESTED              identity AND binding AND freshness AND semantic PASSED
  INDEPENDENTLY_ATTESTED   all of the above PLUS a principal the builder cannot impersonate

"Identity" here means an identity asserted by the EXTERNAL environment and cryptographically
checked — never a CLI argument, a file in the repo, an environment variable the target chose,
or a regex over a git remote. Those are all things a builder can write, and a builder writing
its own identity is the failure mode this whole axis exists to prevent.
"""
import dataclasses
import os
from typing import Any, Dict, Optional, Tuple

from ..models import reasons as R
from ..models.decision import ProvenanceStatus, SemanticStatus
from ..util.canonical import CanonicalizationError, loads_strict


class AuthorityConfigError(ValueError):
    """The configuration is unusable. Never repaired, never defaulted around."""


# =======================================================================================
# What a verifier reports
# =======================================================================================


@dataclasses.dataclass(frozen=True)
class VerifierResult:
    """One verifier's findings. Frozen: an adapter cannot edit a result after reading it.

    `established` means "this verifier completed and its subject checks out". It is NOT a
    claim about provenance status — only `evaluate()` maps facts to a status.

    identity/binding/freshness/principal are None when NOT established. A dict is a positive
    finding and must carry enough detail to audit later; None is the honest default.
    """
    verifier: str
    verifier_version: str
    established: bool
    reason_codes: Tuple[str, ...] = ()
    identity: Optional[Dict[str, Any]] = None
    binding: Optional[Dict[str, Any]] = None
    freshness: Optional[Dict[str, Any]] = None
    principal: Optional[Dict[str, Any]] = None
    detail: str = ""

    def __post_init__(self):
        bad = [c for c in self.reason_codes if c not in R.AUTHORITY_EMITTABLE]
        if bad:
            raise AuthorityConfigError(
                f"verifier {self.verifier!r} emitted non-authority reason codes: {bad}. "
                "A verifier may not author a semantic reason.")
        if not self.established and (self.identity or self.binding or self.freshness
                                     or self.principal):
            raise AuthorityConfigError(
                f"verifier {self.verifier!r} reported established=False but attached positive "
                "findings; an unestablished verifier has nothing to contribute")

    def to_json(self):
        return {
            "verifier": self.verifier, "verifierVersion": self.verifier_version,
            "established": self.established, "reasonCodes": list(self.reason_codes),
            "identity": self.identity, "binding": self.binding, "freshness": self.freshness,
            "principal": self.principal, "detail": self.detail,
        }

    # -- constructors --------------------------------------------------------------------
    @classmethod
    def refusal(cls, verifier, version, reason_code, detail):
        """The ONLY way to report a failure. There is no 'warning' constructor on purpose:
        a verification failure is a refusal, never a note attached to a success."""
        R.require_valid(reason_code)
        return cls(verifier=verifier, verifier_version=version, established=False,
                   reason_codes=(reason_code,), detail=detail)


class Verifier:
    """Abstract verifier. Subclasses implement `verify` and return a `VerifierResult`.

    Contract for implementers:
      * NEVER raise on bad evidence — return a refusal. A raised exception in an optional
        kit would otherwise be able to take down a semantic run that was already final.
      * NEVER return established=True with a swallowed error.
      * `requires` names the shape ids the verifier depends on, so an adapter can report
        exactly which BLOCKED shape is holding it back. An element may be a STRING (this shape
        must be validated) or a TUPLE of strings (at least ONE of these must be, because they
        are repeat captures of a single serialisation — see shapes.require_any_validated). A
        tuple is redundancy, never an escape hatch: it is only correct when every member shares
        a schema, which `selfcheck` asserts.
    """
    name = "verifier"
    version = "0"
    requires: Tuple[Any, ...] = ()

    def verify(self, decision, config) -> VerifierResult:
        raise NotImplementedError

    # convenience for subclasses
    def _refuse(self, reason_code, detail):
        return VerifierResult.refusal(self.name, self.version, reason_code, detail)


# =======================================================================================
# Configuration
# =======================================================================================

_ALLOWED: Dict[str, frozenset] = {
    "$root": frozenset({"schema", "mode", "evidenceDir", "cosign", "rekor", "gh", "oidc",
                        "freshnessMaxAgeSeconds", "expectedSubject", "note",
                        "verifier"}),
    "cosign": frozenset({"versionJson", "bundle", "verifyStdout", "verifyStderr",
                         "verifyExitCode",
                         # v4.1 live execution: the blob to verify, plus the identity
                         # constraint cosign must be given. Running verify-blob with no
                         # constraint verifies that SOMEBODY signed this.
                         "blob", "publicKey", "certificateIdentity",
                         "certificateOidcIssuer"}),
    # `restLogInfo` is GET /api/v1/log. Optional, and only optional because not every operator
    # will have fetched it — but without it the shard offset between an entry's GLOBAL logIndex
    # and its SHARD-LOCAL inclusionProof.logIndex cannot be checked at all. See
    # rekor.check_shard_offset.
    "rekor": frozenset({"version", "restEntry", "restLogInfo", "cliGet", "cliLogInfo"}),
    "gh": frozenset({"version", "repo", "environment", "environmentList",
                     # `_fetch` is a TEST SEAM, underscore-prefixed so it is obviously not
                     # operator configuration. It cannot supply a verdict — only a transport —
                     # and the observation it returns is judged by exactly the same code.
                     "_fetch", "runId", "runAttempt",
                     "environmentSecrets", "environmentName",
                     # v4.2 artifact attestation: WHAT to verify and HOW to reach the
                     # verification material. Deliberately absent: any key for a captured
                     # verify output, an expected exit code, or an identity constraint —
                     # gh is RUN, its real exit code decides, and the identity constraint
                     # is the decision's own subject.
                     "attestationArtifact", "attestationBundle", "attestationTrustedRoot",
                     "attestationDigestAlg"}),
    # WHO is verifying — proved by a cosign signature over the observation challenge, never
    # asserted. Without this section the principal is BLOCKED.
    "verifier": frozenset({"bundle", "publicKey", "certificateIdentity",
                           "certificateOidcIssuer",
                           # two-phase: a phase-1 observation whose contents the verifier's
                           # signature covers. Stronger than the single-phase live mode.
                           "observation"}),
    "oidc": frozenset({"claims", "expectedIssuer", "expectedAudience"}),
    "expectedSubject": frozenset({"repository", "commit", "ownerId", "repositoryId"}),
}

CONFIG_SCHEMA = "shipgate.authority.config/1"

#: Freshness ceiling. An attestation older than this is not evidence about this release.
DEFAULT_FRESHNESS_MAX_AGE_SECONDS = 3600
MAX_FRESHNESS_MAX_AGE_SECONDS = 86400 * 7


def _strict_section(name, raw):
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AuthorityConfigError(f"config section {name!r} must be an object")
    unknown = sorted(set(raw) - _ALLOWED[name])
    if unknown:
        raise AuthorityConfigError(
            f"unknown key(s) in config section {name!r}: {unknown}. "
            f"Known keys: {sorted(_ALLOWED[name])}. Refusing rather than ignoring — a typo "
            "must not silently disable a requirement.")
    return dict(raw)


@dataclasses.dataclass(frozen=True)
class AuthorityConfig:
    """Strict authority configuration.

    Paths point at MACHINE-READABLE tool output that the CI workflow already wrote to disk.
    v4.1 NOTE: the kit now runs cosign itself (`cosignexec.py`) because a captured verdict
    is the operator asserting the answer. The sentence below describes the ORIGINAL design and
    is kept for the reasoning, not as a current statement of behaviour:
    the workflow runs cosign/rekor/gh, the kit
    parses what they produced. See assets/ci/ for the reference workflows.

    `note` is the one free-text key: JSON has no comments and an operator needs somewhere to
    record WHY a config looks the way it does. It is carried into `to_json` and ignored by
    every check.
    """
    mode: str = "ci"                       # "ci" | "independent"
    evidence_dir: str = ""
    cosign: Dict[str, Any] = dataclasses.field(default_factory=dict)
    rekor: Dict[str, Any] = dataclasses.field(default_factory=dict)
    gh: Dict[str, Any] = dataclasses.field(default_factory=dict)
    oidc: Dict[str, Any] = dataclasses.field(default_factory=dict)
    verifier: Dict[str, Any] = dataclasses.field(default_factory=dict)
    freshness_max_age_seconds: int = DEFAULT_FRESHNESS_MAX_AGE_SECONDS
    expected_subject: Dict[str, Any] = dataclasses.field(default_factory=dict)
    note: str = ""
    source: str = "<inline>"

    # -- loading -------------------------------------------------------------------------
    @classmethod
    def from_json(cls, doc, source="<inline>"):
        if not isinstance(doc, dict):
            raise AuthorityConfigError("authority config must be a JSON object")
        unknown = sorted(set(doc) - _ALLOWED["$root"])
        if unknown:
            raise AuthorityConfigError(
                f"unknown top-level key(s) in authority config: {unknown}. "
                f"Known keys: {sorted(_ALLOWED['$root'])}")
        schema = doc.get("schema")
        if schema is not None and schema != CONFIG_SCHEMA:
            raise AuthorityConfigError(
                f"unsupported authority config schema {schema!r}; expected {CONFIG_SCHEMA!r}")
        mode = doc.get("mode", "ci")
        if mode not in ("ci", "independent"):
            raise AuthorityConfigError(
                f"config mode must be 'ci' or 'independent', got {mode!r}")

        age = doc.get("freshnessMaxAgeSeconds", DEFAULT_FRESHNESS_MAX_AGE_SECONDS)
        if not isinstance(age, int) or isinstance(age, bool) or age <= 0:
            raise AuthorityConfigError(
                f"freshnessMaxAgeSeconds must be a positive integer, got {age!r}")
        if age > MAX_FRESHNESS_MAX_AGE_SECONDS:
            raise AuthorityConfigError(
                f"freshnessMaxAgeSeconds {age} exceeds the {MAX_FRESHNESS_MAX_AGE_SECONDS}s "
                "ceiling; an attestation older than that is not evidence about this release")

        evidence_dir = doc.get("evidenceDir", "")
        if not isinstance(evidence_dir, str):
            raise AuthorityConfigError("evidenceDir must be a string path")

        return cls(
            mode=mode,
            evidence_dir=evidence_dir,
            cosign=_strict_section("cosign", doc.get("cosign")),
            rekor=_strict_section("rekor", doc.get("rekor")),
            gh=_strict_section("gh", doc.get("gh")),
            oidc=_strict_section("oidc", doc.get("oidc")),
            verifier=_strict_section("verifier", doc.get("verifier")),
            freshness_max_age_seconds=age,
            expected_subject=_strict_section("expectedSubject", doc.get("expectedSubject")),
            note=str(doc.get("note", "")),
            source=source,
        )

    @classmethod
    def from_text(cls, text, source="<text>"):
        try:
            doc = loads_strict(text)
        except (ValueError, CanonicalizationError) as exc:
            raise AuthorityConfigError(f"authority config is not strict JSON: {exc}") from None
        return cls.from_json(doc, source=source)

    @classmethod
    def from_path(cls, path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise AuthorityConfigError(
                f"authority config unreadable at {path}: {exc.strerror or exc}") from None
        return cls.from_text(text, source=str(path))

    @classmethod
    def coerce(cls, config):
        """Accept an AuthorityConfig, a dict, a path, or None (-> not configured)."""
        if config is None:
            return None
        if isinstance(config, AuthorityConfig):
            return config
        if isinstance(config, dict):
            return cls.from_json(config)
        if isinstance(config, (str, bytes, os.PathLike)):
            return cls.from_path(config)
        raise AuthorityConfigError(
            f"cannot interpret {type(config).__name__} as an authority config")

    # -- helpers -------------------------------------------------------------------------
    def resolve(self, section, key):
        """Resolve a configured evidence path against evidenceDir. None when unset."""
        raw = getattr(self, section, {}).get(key)
        if not raw or not isinstance(raw, str):
            return None
        if os.path.isabs(raw) or not self.evidence_dir:
            return raw
        return os.path.join(self.evidence_dir, raw)

    def configured_sections(self):
        return tuple(s for s in ("cosign", "rekor", "gh", "oidc", "verifier")
                     if getattr(self, s))

    def to_json(self):
        return {
            "schema": CONFIG_SCHEMA, "mode": self.mode, "evidenceDir": self.evidence_dir,
            "cosign": dict(self.cosign), "rekor": dict(self.rekor), "gh": dict(self.gh),
            "oidc": dict(self.oidc),
            "verifier": dict(self.verifier),
            "freshnessMaxAgeSeconds": self.freshness_max_age_seconds,
            "expectedSubject": dict(self.expected_subject), "note": self.note,
            "source": self.source,
        }


# =======================================================================================
# The rule table
# =======================================================================================


@dataclasses.dataclass(frozen=True)
class Rule:
    status: ProvenanceStatus
    requires_semantic_passed: bool
    requires: Tuple[str, ...]
    reason_code: str
    description: str


#: Ordered strongest-first. `evaluate` awards the first rule whose requirements are all met.
RULES: Tuple[Rule, ...] = (
    Rule(
        status=ProvenanceStatus.INDEPENDENTLY_ATTESTED,
        requires_semantic_passed=True,
        requires=("identity", "binding", "freshness", "principal"),
        reason_code=R.AUT_INDEPENDENTLY_ATTESTED,
        description=(
            "A verified external identity, a cryptographic binding to THIS decision digest, "
            "fresh transparency-log evidence, AND a separate principal / trust boundary the "
            "builder cannot impersonate."),
    ),
    Rule(
        status=ProvenanceStatus.CI_ATTESTED,
        requires_semantic_passed=True,
        requires=("identity", "binding", "freshness"),
        reason_code=R.AUT_CI_ATTESTED,
        description=(
            "A verified external CI identity, a cryptographic binding to THIS decision "
            "digest, and fresh transparency-log evidence. NOT independent: the builder and "
            "the attester are the same principal."),
    ),
)

#: What is missing -> which AUT_ code explains it. Ordered by how fundamental the gap is.
_MISSING_REASON = (
    ("identity", R.AUT_IDENTITY_NOT_ESTABLISHED),
    ("binding", R.AUT_BINDING_MISMATCH),
    ("freshness", R.AUT_FRESHNESS_EXPIRED),
    ("principal", R.AUT_PRINCIPAL_NOT_DISTINCT),
)

_ORDER = {
    ProvenanceStatus.NONE: 0,
    ProvenanceStatus.UNAVAILABLE: 1,
    ProvenanceStatus.CI_ATTESTED: 2,
    ProvenanceStatus.INDEPENDENTLY_ATTESTED: 3,
}


def facts(results):
    """Merge verifier results into the four fact slots. Only ESTABLISHED verifiers contribute."""
    merged = {"identity": None, "binding": None, "freshness": None, "principal": None}
    for res in results:
        if not res.established:
            continue
        for slot in merged:
            value = getattr(res, slot)
            if value and merged[slot] is None:
                merged[slot] = dict(value, verifier=res.verifier)
    return merged


def _principal_is_externally_authorized(principal):
    """True only when something OUTSIDE the target authorised this verifier.

    Today that means: the observation was signed under an externally issued identity (a
    Fulcio certificate from a pinned OIDC issuer) AND that identity appears on a list handed
    to the verifier's own process rather than read from the repository under judgement.

    No shipped configuration satisfies this, which is the point. The remaining work — a
    policy signed outside the target, fetched from a pinned location, verified against an
    identity embedded in the release, bound to the repository and versioned against rollback
    — is not built. Until it is, `INDEPENDENTLY_ATTESTED` is unreachable rather than
    reachable by anyone willing to run `cosign generate-key-pair`.
    """
    if not isinstance(principal, dict):
        return False
    binding = principal.get("binding")
    if not isinstance(binding, dict):
        return False
    return binding.get("verifierAuthorized") is True


def _same_party(principal, identity):
    """True when the observing verifier is the identity being attested.

    Compared on the strings each side already carries: the verifier identity recorded in the
    observation's binding, against the subject inside the signing certificate. A match is not
    proof of misconduct — a solo maintainer legitimately IS both — but it is proof that the
    result is not INDEPENDENT, and that is the only claim being withheld.
    """
    if not isinstance(principal, dict) or not isinstance(identity, dict):
        return False
    binding = principal.get("binding")
    who = (binding or {}).get("verifierIdentity") if isinstance(binding, dict) else None
    if not who:
        return False

    # A POLICY-PINNED KEY RESOLVES THROUGH THE POLICY, deliberately. A `key:<digest>`
    # identity carries no principal to compare — key-vs-workflow is unresolvable, and the
    # ambiguity rule below would read it as the same party, making a pinned key permanently
    # unable to reach independence. But the pin IS an external assertion of separation: the
    # policy root — outside the target's reach by construction — signed a document naming
    # this exact key as the verifier for this repository. An organisation that pins the
    # builder's own key has failed at the authorization layer, which the policy root owns;
    # that failure mode is identical to the org authorizing the builder's workflow as its
    # own verifier in a keyless deployment, and no string comparison here could catch
    # either. Three conditions, all required: the identity IS a key, the policy travelled
    # in the binding (i.e. it verified against the pinned root), and that policy pins this
    # exact key. An unpinned key falls through to the ambiguity rule and stays SAME PARTY.
    if str(who).startswith("key:") and isinstance(binding, dict) \
            and binding.get("verifierAuthorized") is True:
        pinned = ((binding.get("policy") or {}).get("authorizedVerifiers") or ())
        from . import enforcement
        if any(enforcement.normalise_identity(entry) == enforcement.normalise_identity(who)
               for entry in pinned):
            return False

    # NORMALISED, not string-compared. Comparing raw strings answers "are these spellings
    # different", which is not the question. GitHub gives one actor several true names — a
    # login, a numeric id, a workflow ref, a sha-pinned ref — so an attacker needs no forgery
    # to defeat a string check: they spell themselves differently on each side.
    from . import principals
    builder = ""
    for key in ("subject", "san", "identity", "issuerSubject", "repository"):
        if identity.get(key):
            builder = str(identity[key])
            break
    if not builder:
        return False
    left = principals.normalise(builder, identity.get("ids"))
    right = principals.normalise(str(who), (binding or {}).get("ids"))
    try:
        same, _ = principals.same_principal(left, right)
    except principals.AmbiguousPrincipal:
        # AN UNKNOWN IS TREATED AS THE SAME PARTY, which is the direction that withholds a
        # claim rather than granting one. "We could not establish that these are different
        # people" must not read as "these are different people".
        return True
    return same


def _principal_is_authenticated(principal):
    """True only for a principal a verifier OBSERVED and BOUND to this decision.

    Three keys, all set together on one code path:

      authenticated  the observing verifier's own assertion that it looked
      observedFrom   the URL it read, so the claim names its source
      binding        decision digest, commit, run and timestamp, so the observation cannot be
                     replayed onto a different decision

    Absence is not an error and not a downgrade to a weaker award — it removes the fact
    entirely, because an unauthenticated principal is not a weaker principal. It is not one.
    """
    if not isinstance(principal, dict):
        return False
    if principal.get("authenticated") is not True:
        return False
    if not principal.get("observedFrom"):
        return False
    binding = principal.get("binding")
    if not isinstance(binding, dict) or not binding.get("decisionDigest"):
        return False
    # WHO observed must be proved, not asserted. `verifierIdentity` defaulted to a constant
    # USER_AGENT string, which made `_same_party` vacuous — a constant never equals a
    # builder's subject, so every observer looked distinct including the builder itself.
    # The identity must now come from a signature this kit verified.
    if binding.get("verifierIdentityVerified") is not True:
        return False
    return bool(binding.get("verifierIdentity"))


def evaluate(semantic_status, results, ceiling=ProvenanceStatus.INDEPENDENTLY_ATTESTED):
    """Map verifier facts to (ProvenanceStatus, reason_codes, detail).

    `ceiling` clamps the result — the CI adapter passes CI_ATTESTED so that no combination of
    verifier output can make it emit INDEPENDENTLY_ATTESTED.

    This function NEVER returns NONE: NONE means "authority was not requested", which is a
    property of the decision, not something an adapter may assert.
    """
    results = tuple(results)
    codes = []
    for res in results:
        for code in res.reason_codes:
            if code not in codes:
                codes.append(code)

    if semantic_status is not SemanticStatus.PASSED:
        # Checked FIRST and unconditionally: attesting a failed decision is impossible, and
        # we do not even look at the verifier output before saying so.
        return (ProvenanceStatus.UNAVAILABLE,
                tuple([R.AUT_SEMANTIC_NOT_PASSED] + [c for c in codes
                                                     if c != R.AUT_SEMANTIC_NOT_PASSED]),
                f"semantic status is {getattr(semantic_status, 'value', semantic_status)!r}; "
                "an authority adapter may not attest a decision that did not pass on the "
                "merits")

    have = facts(results)

    # AUTHENTICITY GATE, applied before any rule is considered.
    #
    # `facts()` merges whatever the verifiers put in each slot; it cannot tell a fact that was
    # OBSERVED from one that was constructed. An external audit demonstrated the consequence:
    # four hand-built VerifierResult objects, with no files and no forgery, were awarded
    # INDEPENDENTLY_ATTESTED — because the only question asked was whether the slot was
    # non-empty.
    #
    # So the slot being filled is no longer sufficient. A principal must carry proof that a
    # verifier observed it live and bound the observation to this decision. Only
    # `GithubEnvironmentPrincipalVerifier`'s live path sets those keys, and it sets them from
    # an HTTP response it made itself.
    principal = have.get("principal")
    # INDEPENDENCE ADDITIONALLY REQUIRES EXTERNAL AUTHORIZATION.
    #
    # `_principal_is_authenticated` answers BINDING — did a verifier observe this and sign
    # it. That is necessary and it is not sufficient. An external review put the missing
    # question plainly: who authorised this verifier to confer independence at all? Until a
    # policy signed outside the target repository names the permitted verifier identities,
    # the honest answer is nobody, and a self-issued key is its own source of authority.
    #
    # So the strongest a bound-but-unauthorised observation can reach is CI_ATTESTED. This
    # is a DEMOTION, deliberately: the mechanism is built and the trust root is not, and
    # shipping the mechanism as though the trust root existed is the exact substitution this
    # whole round has been about.
    if principal and not _principal_is_externally_authorized(principal):
        have = dict(have)
        have.pop("principal", None)
        if R.AUT_PRINCIPAL_NOT_DISTINCT not in codes:
            codes.append(R.AUT_PRINCIPAL_NOT_DISTINCT)
        principal = None
    if principal and not _principal_is_authenticated(principal):
        have = dict(have)
        have.pop("principal", None)
        if R.AUT_PRINCIPAL_NOT_DISTINCT not in codes:
            codes.append(R.AUT_PRINCIPAL_NOT_DISTINCT)
        principal = None
    elif principal and _same_party(principal, have.get("identity")):
        # PRODUCER != VERIFIER. An observation is only independent if the party that made it
        # is not the party being vouched for. A verifier running as the builder's own identity
        # can observe truthfully all day and still be the builder checking their own work,
        # which is the thing the word "independent" is supposed to exclude.
        have = dict(have)
        have.pop("principal", None)
        if R.AUT_PRINCIPAL_NOT_DISTINCT not in codes:
            codes.append(R.AUT_PRINCIPAL_NOT_DISTINCT)
        principal = None

    # FULL POLICY ENFORCEMENT — every field, one function, applied where every fact is
    # visible at once. The gates above answered "is this observation real, signed, and made
    # by someone other than the builder". This one answers "does the externally signed policy
    # actually permit THIS award": the builder must be on authorizedBuilders (from the
    # VERIFIED certificate identity, never configuration), the observed environment must be
    # the policy-required one, the numeric repository id must match when pinned, the validity
    # window must hold against externally established time, and rollback protection must be
    # in place. Any failure DEMOTES the award below independence — v4.1 parsed several of
    # these fields and enforced none of them, which made the policy read stronger than it was.
    if principal:
        from . import enforcement
        binding = principal.get("binding") if isinstance(principal.get("binding"), dict) \
            else {}
        identity_fact = have.get("identity") or {}
        builder_identity = ""
        if (isinstance(identity_fact, dict)
                and identity_fact.get("kind") in ("fulcio-keyless-certificate",
                                                  "gh-attestation-certificate")):
            # The certificate SAN is the builder's workflow identity, out of signed DER that
            # cosign (or GitHub's own verifier, actually run) checked — the ONLY admissible
            # sources for the authorizedBuilders check. Config values are not on this list
            # and cannot get on it.
            builder_identity = str(identity_fact.get("sanUri") or "")
        fresh = have.get("freshness") or {}
        external_time, time_source = None, ""
        if (isinstance(fresh, dict)
                and isinstance(fresh.get("integratedTime"), int)
                and not isinstance(fresh.get("integratedTime"), bool)):
            # integratedTime from an entry whose inclusion proof recomputed a root that a
            # checkpoint signed by the pinned Rekor key attests. The SET itself remains
            # shape-checked only, and that caveat is recorded in the freshness fact.
            external_time = fresh["integratedTime"]
            time_source = "rekor-integrated-time"
        builder_side_ids = []
        ids = identity_fact.get("ids") if isinstance(identity_fact, dict) else None
        if isinstance(ids, dict):
            for key in ("ownerId", "actorId"):
                if ids.get(key) is not None:
                    builder_side_ids.append(str(ids[key]))
        verdict = enforcement.enforce_award(
            binding.get("policy"),
            verifier_identity=str(binding.get("verifierIdentity") or ""),
            builder_identity=builder_identity,
            observed_environment=(binding.get("environment")
                                  or principal.get("environment")),
            observed_repository_id=binding.get("repositoryId"),
            external_time=external_time,
            external_time_source=time_source,
            deployment=principal.get("deployment"),
            expected_commit=str(binding.get("commit") or ""),
            expected_run_id=str(binding.get("runId") or ""),
            builder_ids=tuple(builder_side_ids),
            observation_mode=str(binding.get("observationMode") or ""))
        if verdict["authorized"]:
            have = dict(have)
            have["principal"] = dict(principal, policyEnforcement=verdict)
        else:
            have = dict(have)
            have.pop("principal", None)
            for code in verdict["reasonCodes"]:
                if code not in codes:
                    codes.append(code)

    for rule in RULES:
        if _ORDER[rule.status] > _ORDER[ceiling]:
            continue
        if rule.requires_semantic_passed and semantic_status is not SemanticStatus.PASSED:
            continue        # belt and braces: the early return above already handled this
        missing = [slot for slot in rule.requires if not have.get(slot)]
        if missing:
            continue
        # Drop codes the award CONTRADICTS. One verifier saying "identity not established"
        # while another established it is not a warning to carry alongside AUT_CI_ATTESTED —
        # it is a statement the result disproves, and shipping both would make the reason
        # codes unreadable. Codes about anything else (a blocked shape elsewhere, say) stay.
        contradicted = {code for slot, code in _MISSING_REASON if have.get(slot)}
        awarded = [rule.reason_code] + [c for c in codes
                                        if c != rule.reason_code and c not in contradicted]
        return rule.status, tuple(awarded), rule.description

    # Nothing was awarded. Explain the most fundamental gap first, and keep every reason the
    # verifiers already gave — a refusal must say what would have to change.
    reachable = [r for r in RULES if _ORDER[r.status] <= _ORDER[ceiling]]
    needed = reachable[-1].requires if reachable else ()
    for slot, code in _MISSING_REASON:
        if slot in needed and not have.get(slot) and code not in codes:
            codes.append(code)
    if not codes:
        codes.append(R.AUT_NOT_CONFIGURED)
    missing = [slot for slot in needed if not have.get(slot)]
    return (ProvenanceStatus.UNAVAILABLE, tuple(codes),
            "no rule was satisfied; missing: " + (", ".join(missing) or "nothing"))


def rule_table_json():
    return [
        {"status": r.status.value, "requiresSemanticPassed": r.requires_semantic_passed,
         "requires": list(r.requires), "reasonCode": r.reason_code,
         "description": r.description}
        for r in RULES
    ]


__all__ = [
    "AuthorityConfig", "AuthorityConfigError", "CONFIG_SCHEMA",
    "DEFAULT_FRESHNESS_MAX_AGE_SECONDS", "RULES", "Rule", "Verifier", "VerifierResult",
    "evaluate", "facts", "rule_table_json",
]
