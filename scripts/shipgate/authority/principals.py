"""Normalising principals, so two spellings of one party cannot look like two parties.

WHY STRING COMPARISON IS NOT ENOUGH. `_same_party` compared identity strings, which answers
"are these two strings different" and not "are these two principals different". GitHub gives
the same actor several true names — a login, a numeric id, an `@refs/heads/main` workflow
reference, a `@<sha>` pin of the same workflow, a URL with or without a trailing slash. An
attacker does not need to forge anything to defeat a string comparison: they pick a different
true spelling of themselves for the builder and the verifier, and the gate reports two
principals where there is one.

Numeric ids are the stable form and strings are not. `login` changes when somebody renames
their account; `id` does not. So identities normalise to ids where an id is available, and the
comparison is refused rather than guessed where it is not — an unresolvable comparison is an
unknown, and reporting an unknown as "distinct" is how a self-verified release passes.

WHAT IS DELIBERATELY NOT DONE HERE. No network. This module resolves what is already inside an
identity string or an observation; it never asks GitHub who someone is, because that call
belongs in `live.py` where its failure is a BLOCKED outcome rather than a silent fallback.
"""
import re
from typing import Any, Dict, Optional, Tuple

#: A GitHub Actions workflow identity, as Fulcio writes it into a certificate SAN:
#:   https://github.com/OWNER/REPO/.github/workflows/FILE.yml@REF
_WORKFLOW = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
    r"(?P<path>\.github/workflows/[^@]+)@(?P<ref>.+)$")

#: `repo:OWNER/REPO:ref:REF` — the OIDC `sub` claim shape.
_SUB_CLAIM = re.compile(r"^repo:(?P<owner>[^/]+)/(?P<repo>[^:]+):(?P<rest>.+)$")


class AmbiguousPrincipal(Exception):
    """Two identities could not be compared. Never resolved by guessing."""


def normalise(identity: str, ids: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Break an identity string into the parts that can be compared.

    `ids` optionally supplies numeric ids observed live (`ownerId`, `repositoryId`,
    `actorId`). Where present they win, because a login is a display name and an id is not.
    """
    ids = ids or {}
    raw = (identity or "").strip()
    record: Dict[str, Any] = {"raw": raw, "kind": "opaque"}
    if not raw:
        return record

    match = _WORKFLOW.match(raw.rstrip("/"))
    if match:
        record.update(kind="workflow", owner=match.group("owner"),
                      repository=match.group("repo"), workflow=match.group("path"),
                      ref=match.group("ref"))
    else:
        match = _SUB_CLAIM.match(raw)
        if match:
            record.update(kind="sub-claim", owner=match.group("owner"),
                          repository=match.group("repo"))
    for key in ("ownerId", "repositoryId", "actorId"):
        if ids.get(key) is not None:
            record[key] = str(ids[key])
    return record


def same_principal(left: Dict[str, Any], right: Dict[str, Any]) -> Tuple[bool, str]:
    """(same, why). Raises `AmbiguousPrincipal` when the answer cannot be established.

    Refusing to answer is the important behaviour. The caller uses this to decide whether a
    verifier is independent of a builder, and the safe reading of "I could not tell" is NOT
    "they are different" — that is precisely the direction an attacker wants.
    """
    if not left.get("raw") or not right.get("raw"):
        raise AmbiguousPrincipal("one side has no identity at all, so nothing can be compared")

    if left["raw"].rstrip("/") == right["raw"].rstrip("/"):
        return True, "identical identities"

    # Numeric ids are authoritative when both sides carry them.
    for key in ("actorId", "repositoryId", "ownerId"):
        a, b = left.get(key), right.get(key)
        if a is not None and b is not None:
            if a == b:
                return True, f"same {key} ({a}) under different spellings"

    both_workflows = left.get("kind") == "workflow" and right.get("kind") == "workflow"
    if both_workflows:
        same_repo = (left.get("owner", "").lower() == right.get("owner", "").lower()
                     and left.get("repository", "").lower()
                     == right.get("repository", "").lower())
        if same_repo:
            # SAME REPOSITORY, DIFFERENT REF OR WORKFLOW FILE. This is the case that matters:
            # a repository that both builds and verifies itself is one principal wearing two
            # hats, whatever the workflow file is called. Treating build.yml and verify.yml in
            # one repo as two principals is the whole self-verification loophole.
            return True, (f"both identities are workflows in {left.get('owner')}/"
                          f"{left.get('repository')}; a repository verifying itself is one "
                          f"principal, not two")
        if left.get("ownerId") is None or right.get("ownerId") is None:
            # Different owner LOGINS, and no ids to confirm they are really different parties.
            # A login can be renamed; without ids this is an unknown.
            raise AmbiguousPrincipal(
                f"{left.get('owner')!r} and {right.get('owner')!r} are different logins, but "
                f"no numeric owner ids were observed to confirm they are different parties. "
                f"A login is a display name. Supply ownerId from a live observation.")
        return False, (f"different owners: {left.get('owner')} (id {left.get('ownerId')}) "
                       f"and {right.get('owner')} (id {right.get('ownerId')})")

    raise AmbiguousPrincipal(
        f"cannot compare a {left.get('kind')} identity with a {right.get('kind')} one; "
        f"normalise both to workflow references or supply numeric ids")


def describe() -> str:
    return "\n".join([
        "PRINCIPAL NORMALISATION — one party, however it spells itself.",
        "",
        "  Compared on numeric ids where available, because a login is a display name that",
        "  can be renamed and an id cannot.",
        "",
        "  Two workflows in the SAME repository are ONE principal. A repository that builds",
        "  and verifies itself is not two parties, whatever the workflow files are called.",
        "",
        "  An unresolvable comparison RAISES. 'I could not tell' must never be read as",
        "  'they are different' — that is the direction a self-verifying release needs.",
    ])
