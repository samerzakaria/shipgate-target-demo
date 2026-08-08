"""The external authorization policy — who may confer independence, decided outside the target.

THE QUESTION THIS ANSWERS. Binding proves a verifier signed this exact observation.
Authorization answers a different question entirely: who said that verifier may vouch for
anything? Until v4.1 nothing answered it, and a verifier presented a key it had generated
itself. A self-issued key is its own source of authority, which is not a source of authority.

WHAT A POLICY IS. A signed document, produced outside the repository under judgement, naming
the builder and verifier identities permitted for that repository:

    {
      "schema": "shipgate.authority.policy/1",
      "repository": "owner/repository",
      "version": 7,
      "authorizedBuilders":  ["https://github.com/owner/repo/.github/workflows/build.yml@refs/heads/main"],
      "authorizedVerifiers": ["https://github.com/sec-org/verify/.github/workflows/verify.yml@refs/heads/main"],
      "requiredEnvironment": "production",
      "notBefore": 1786032000,
      "notAfter": 1817568000
    }

EVERY FIELD IS LOAD-BEARING OR IT IS NOT IN THE SCHEMA. v4.1 parsed `minimumAuthority` and
enforced nothing with it; v4.2 removes it rather than enforcing it, because a policy is a set
of CONSTRAINTS and "minimumAuthority" was a request for an outcome. A policy carrying it is
now refused as an unknown key — schema version 1 is final. The optional `repositoryId` pins
the GitHub numeric repository id, which survives renames and transfers the way `owner/name`
does not; when present it must match the id observed live from GitHub. `notBefore`/`notAfter`
are a validity window evaluated against EXTERNALLY ESTABLISHED time only (a checkpoint-verified
Rekor integratedTime, or a platform-signed timestamp) — never the verifier's own clock.
Enforcement of every field lives in ONE place: `authority/enforcement.py`.

WHAT MAKES IT LOAD-BEARING, and each of these is a refusal rather than a warning:

  SIGNED BY A PINNED ROOT. The policy's signature is checked against an identity embedded in
  THIS release (`POLICY_ROOTS`). An operator cannot nominate the key that authorises them —
  that is the loop this module exists to break — so there is no configuration key that adds
  a root, exactly as with the Rekor trust root.

  BOUND TO THE REPOSITORY. A policy valid for one repository must not authorise another. Real
  policies get copied between repos, and a check that ignored the subject would make that a
  silent privilege escalation.

  UNMODIFIABLE FROM INSIDE THE TARGET. The policy is NOT read from the authority config, from
  the repository, or from any state file — all of which the party being judged can write. It
  comes from a path given to the verifier's own process, or from a pinned URL.

  ROLLBACK-PROTECTED. Versions move forward only. A revoked verifier stays revoked, so
  replaying yesterday's policy after losing authorisation is refused rather than accepted as
  a valid older document.

WHAT THIS MODULE CANNOT DO, stated plainly because it is the honest boundary: it cannot decide
WHO SHOULD BE on a policy. That is an organisational judgement and no code makes it. What it
does is ensure the answer comes from somewhere the target cannot reach.
"""
import hashlib
import json
import os
from typing import Any, Dict, Optional, Tuple

SCHEMA = "shipgate.authority.policy/1"

#: Where a policy may come from. An ENVIRONMENT VARIABLE on the verifier's process, never the
#: authority config — that file lives in the repository being judged.
POLICY_PATH_ENV = "SHIPGATE_AUTHORITY_POLICY"
POLICY_BUNDLE_ENV = "SHIPGATE_AUTHORITY_POLICY_BUNDLE"

#: Where the highest version seen is remembered, so a rollback is detectable across runs.
POLICY_STATE_ENV = "SHIPGATE_AUTHORITY_POLICY_STATE"

#: Identities permitted to SIGN a policy. Empty in this release, and that is the whole reason
#: INDEPENDENTLY_ATTESTED is unreachable: there is no root, so no policy can be trusted, so no
#: verifier can be authorised.
#:
#: It is empty rather than populated with a placeholder on purpose. A plausible-looking root
#: nobody controls would make the machinery appear complete while authorising nothing, and
#: somebody would eventually point a config at it. An adopter who runs their own trust root
#: forks this constant deliberately, which is a decision with a diff attached.
POLICY_ROOTS: Tuple[Dict[str, str], ...] = ()

#: Issuers a policy signature may come from. Pinned, not widenable.
POLICY_ISSUERS = (
    "https://token.actions.githubusercontent.com",
    "https://accounts.google.com",
)

_ALLOWED_KEYS = frozenset({
    "schema", "repository", "version", "authorizedBuilders", "authorizedVerifiers",
    "requiredEnvironment", "repositoryId", "note", "notBefore", "notAfter",
})


class PolicyError(Exception):
    """The policy could not be loaded, verified, or does not apply. Always a refusal."""


class NoPolicy(PolicyError):
    """No policy was supplied. BLOCKED — distinct from a policy that failed verification."""


def configured() -> bool:
    return bool(os.environ.get(POLICY_PATH_ENV))


def available() -> Tuple[bool, str]:
    """(usable, detail). Never raises, so `doctor` can report it."""
    if not POLICY_ROOTS:
        return False, (
            "no policy signing root is embedded in this release, so no external policy can "
            "be trusted and no verifier can be authorised. INDEPENDENTLY_ATTESTED is "
            "unreachable by construction. An adopter running their own trust root forks "
            "`POLICY_ROOTS` in authority/policy.py.")
    if not configured():
        return False, (f"{POLICY_PATH_ENV} is unset; no external authorization policy was "
                       f"supplied to this verifier")
    return True, "an external authorization policy is configured and a signing root is pinned"


def _read_document(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise PolicyError(f"policy {path} is unreadable: {exc}")
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise PolicyError(f"policy {path} is not JSON: {exc}")
    if not isinstance(document, dict):
        raise PolicyError(f"policy {path} is not an object")
    unknown = sorted(set(document) - _ALLOWED_KEYS)
    if unknown:
        raise PolicyError(
            f"policy {path} carries unknown key(s) {unknown}; a typo must not silently "
            f"disable an authorization requirement")
    if document.get("schema") != SCHEMA:
        raise PolicyError(f"policy schema is {document.get('schema')!r}, expected {SCHEMA!r}")
    # v4.2: `authorizedBuilders` and `requiredEnvironment` are REQUIRED. Both used to be
    # optional-and-decorative, which meant a policy could authorise a verifier while saying
    # nothing about who may build or where a release must pass through — and a constraint a
    # policy does not state is a constraint nobody enforces. A policy that genuinely wants
    # no builder constraint does not exist in schema/1; write the builder list.
    for field in ("repository", "version", "authorizedBuilders", "authorizedVerifiers",
                  "requiredEnvironment"):
        if field not in document:
            raise PolicyError(f"policy is missing required field {field!r}")
    if not isinstance(document.get("version"), int) or isinstance(document.get("version"), bool) \
            or document["version"] < 1:
        raise PolicyError("policy version must be a positive integer")
    for field in ("authorizedBuilders", "authorizedVerifiers"):
        value = document.get(field)
        if (not isinstance(value, list) or not value
                or not all(isinstance(x, str) and x.strip() for x in value)):
            raise PolicyError(f"policy {field} must be a non-empty list of identity strings")
    env = document.get("requiredEnvironment")
    if not isinstance(env, str) or not env.strip():
        raise PolicyError("policy requiredEnvironment must be a non-empty string naming the "
                          "protected deployment environment a release must pass through")
    repo_id = document.get("repositoryId")
    if repo_id is not None and (not isinstance(repo_id, int) or isinstance(repo_id, bool)
                                or repo_id < 1):
        raise PolicyError("policy repositoryId must be a positive integer (the GitHub "
                          "numeric repository id) when present")
    for field in ("notBefore", "notAfter"):
        value = document.get(field)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)
                                  or value < 0):
            raise PolicyError(f"policy {field} must be a non-negative unix timestamp")
    nb, na = document.get("notBefore"), document.get("notAfter")
    if nb is not None and na is not None and nb >= na:
        raise PolicyError(f"policy validity window is empty: notBefore {nb} is not before "
                          f"notAfter {na}")
    return document


def normalise_repository(value: str) -> str:
    """One spelling for one repository. GitHub owner/name is case-insensitive; a policy that
    refused `Owner/Repo` while authorising `owner/repo` would be comparing spellings, not
    repositories."""
    return (value or "").strip().strip("/").lower()


def _verify_signature(path: str, bundle: Optional[str]) -> Dict[str, Any]:
    """Verify the policy against a PINNED root, or refuse.

    With no root pinned there is nothing to verify against, and this refuses rather than
    falling back to an unsigned read. A policy nobody signed is an operator-supplied file
    with extra ceremony, and treating it as authority would rebuild the loop one level up.
    """
    if not POLICY_ROOTS:
        raise PolicyError(
            "no policy signing root is embedded in this release, so this policy cannot be "
            "verified. It is REFUSED rather than read unsigned: an unsigned policy is an "
            "operator-supplied file, and the operator is who the policy exists to constrain.")
    if not bundle:
        raise PolicyError(
            f"{POLICY_BUNDLE_ENV} is unset; the policy carries no signature to check")
    try:
        from . import cosignexec
    except ImportError as exc:  # pragma: no cover
        raise PolicyError(f"cosign runner unavailable: {exc}")

    last = ""
    for root in POLICY_ROOTS:
        try:
            if root.get("publicKeyPath"):
                # A KEYED policy root. Weaker than keyless — nothing external asserts who
                # holds the key — but the key is PINNED IN THIS RELEASE, which is a
                # deliberate fork-the-constant decision by the adopter, not something any
                # configuration can inject. It exists for two deployments: an adopter whose
                # security organisation manages its own signing key, and the test root the
                # shipped suite installs to prove the strongest path is reachable at all.
                result = cosignexec.verify_blob(
                    path, bundle, key_path=root["publicKeyPath"])
                if result["verified"]:
                    key_digest = "key:unreadable"
                    try:
                        with open(root["publicKeyPath"], "rb") as fh:
                            key_digest = ("key:"
                                          + hashlib.sha256(fh.read()).hexdigest()[:32])
                    except OSError:
                        pass
                    return {"signedBy": root.get("identity") or key_digest,
                            "issuer": "",
                            "rootKind": "pinned-key"}
            else:
                result = cosignexec.verify_blob(
                    path, bundle,
                    certificate_identity=root.get("identity"),
                    certificate_oidc_issuer=root.get("issuer"))
                if result["verified"]:
                    return {"signedBy": root.get("identity"), "issuer": root.get("issuer"),
                            "rootKind": "keyless"}
        except cosignexec.CosignExecError as exc:
            last = str(exc)
            continue
        last = result["detail"]
    raise PolicyError(f"the policy is not signed by any pinned root: {last}")


def _check_rollback(document: Dict[str, Any]) -> Dict[str, Any]:
    """Versions move forward only.

    Without this, revocation does not work: an operator who lost authorisation replays the
    policy from before they lost it, and every other check passes because that document is
    genuinely valid and genuinely signed. Highest-seen is remembered outside the target for
    the same reason the policy is.
    """
    state_path = os.environ.get(POLICY_STATE_ENV)
    version = document["version"]
    if not state_path:
        return {"rollbackChecked": False,
                "rollbackNote": (f"{POLICY_STATE_ENV} is unset, so no highest-seen version is "
                                 f"remembered and a replayed older policy would not be "
                                 f"detected")}
    seen = {}
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as fh:
                seen = json.load(fh)
        except (OSError, ValueError) as exc:
            raise PolicyError(f"policy state {state_path} is unreadable: {exc}")
    key = document["repository"]
    highest = seen.get(key, 0)
    if version < highest:
        raise PolicyError(
            f"policy version {version} is older than version {highest} already seen for "
            f"{key}; a replayed policy would reinstate authorisations that were revoked")
    if version > highest:
        seen[key] = version
        try:
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(seen, fh, indent=2, sort_keys=True)
        except OSError as exc:
            raise PolicyError(f"policy state {state_path} is not writable: {exc}")
    return {"rollbackChecked": True, "highestSeenVersion": max(version, highest)}


def load(repository: str, path: Optional[str] = None,
         bundle: Optional[str] = None) -> Dict[str, Any]:
    """Load, verify and apply the external policy for `repository`. Raises on any doubt."""
    path = path or os.environ.get(POLICY_PATH_ENV)
    if not path:
        raise NoPolicy(
            f"{POLICY_PATH_ENV} is unset. Independence requires a policy signed outside this "
            f"repository naming who may verify it; without one, nothing authorises any "
            f"verifier and the run stops at CI_ATTESTED.")
    document = _read_document(path)
    signature = _verify_signature(path, bundle or os.environ.get(POLICY_BUNDLE_ENV))

    if normalise_repository(document["repository"]) != normalise_repository(repository):
        raise PolicyError(
            f"the policy authorises {document['repository']!r} but this decision is about "
            f"{repository!r}; a policy copied between repositories must not carry its "
            f"authorisations with it")

    rollback = _check_rollback(document)
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return {
        "schema": SCHEMA,
        "repository": document["repository"],
        "repositoryId": document.get("repositoryId"),
        "version": document["version"],
        "authorizedBuilders": tuple(document.get("authorizedBuilders") or ()),
        "authorizedVerifiers": tuple(document.get("authorizedVerifiers") or ()),
        "requiredEnvironment": document.get("requiredEnvironment") or "",
        "notBefore": document.get("notBefore"),
        "notAfter": document.get("notAfter"),
        "policyDigest": digest,
        "signature": signature,
        **rollback,
    }


def authorizes_verifier(policy: Dict[str, Any], identity: str) -> Tuple[bool, str]:
    """Delegates to the ONE enforcement implementation. Kept as a name because callers and
    tests know it; the logic lives in `enforcement.verifier_authorized` so there is exactly
    one place a membership decision can be made."""
    from . import enforcement
    return enforcement.verifier_authorized(policy, identity)


def describe() -> str:
    usable, detail = available()
    return "\n".join([
        "EXTERNAL AUTHORIZATION POLICY — who may confer independence.",
        "",
        f"  Status: {'configured' if usable else 'NOT AVAILABLE'} — {detail}",
        "",
        f"  Source: {POLICY_PATH_ENV} (the verifier's own environment), signature in",
        f"  {POLICY_BUNDLE_ENV}, rollback state in {POLICY_STATE_ENV}.",
        "  Never read from the authority config or the repository: the party being judged",
        "  must not be able to write its own authorisation.",
        "",
        "  Refused: an unsigned policy, one signed by an unpinned root, one naming a",
        "  different repository, and one older than a version already seen.",
        "",
        "  NOT decided here: who SHOULD be on the policy. That is an organisational",
        "  judgement, and no code makes it.",
    ])
