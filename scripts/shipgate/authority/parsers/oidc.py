"""GitHub Actions OIDC claim-set parsing — and a refusal to call it identity.

The shape is now VALIDATED against a real capture (`oidc.github.claims.v1`), so this module
really parses. What has NOT changed, and must not:

    AN UNVERIFIED JWT IS NOT AN IDENTITY.

Verifying the token would need GitHub's JWKS (a network fetch) and RSA verification (a crypto
dependency), both outside this release's bounded scope. What this kit receives is a claim set
someone decoded and wrote to a file. Anyone who can write that file can write any claims they
like. So `establishes_identity()` returns False, always, and says why.

WHAT CI_ATTESTED CAN REST ON, THEN. Not this. Identity comes from the KEYLESS COSIGN path,
where Fulcio binds the OIDC identity into a short-lived certificate, the certificate is logged
to a CT log, and `cosign verify-blob --certificate-identity --certificate-oidc-issuer` checks
the whole chain against Sigstore's roots. `parsers/cosign.py` reads the identity out of that
certificate; `verifiers.CosignBundleVerifier` composes it with cosign's own verdict, because
the parse says WHICH identity and only cosign's verdict says it is a TRUSTED one.

So what is this module FOR? Two things, both real:

  * CORROBORATION. The claim set and the certificate describe the same signing event from two
    directions. If they disagree, something is wrong and the run is refused. On the shipped
    (sanitized) capture six fields agree and four disagree — see SHAPES.json.
  * EARLY, PRECISE REFUSAL. Wrong issuer, wrong audience, a self-hosted runner, a token that
    was not live at signing time, or a `repository` claim that is not the decision's subject —
    each is caught here with its own reason code instead of a vague failure later.

TIME. A recorded claim set is always expired by the time anything reads it — GitHub tokens
live about five minutes. So liveness is judged AT SIGNING TIME (the Rekor `integratedTime`)
when the caller can supply it, and against the wall clock only when judging a live token.
Checking a stored token against "now" would reject every claim set ever archived, which is
strictness that means nothing.
"""
from ...models import reasons as R
from .. import shapes
from . import _common as C

SHAPE_CLAIMS = "oidc.github.claims.v1"

#: The only issuer this kit knows. Anything else is a different trust root entirely.
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"

#: Claims that must be present for a claim set to be worth looking at at all.
REQUIRED_CLAIMS = ("iss", "aud", "sub", "exp", "iat", "repository", "repository_id",
                   "repository_owner_id", "job_workflow_ref", "workflow_ref", "sha", "ref",
                   "run_id", "runner_environment")

UNVERIFIED_JWT_DETAIL = (
    "the claim set is well formed, but this kit cannot verify the JWT signature (that needs "
    "GitHub's JWKS and asymmetric crypto, both outside the bounded scope of this release). "
    "Unverified claims are CORROBORATION, never identity. Identity must come from the "
    "Fulcio-backed keyless cosign path, where cosign verifies the certificate chain.")


def parse_claims(raw, registry=None):
    """Parse a claim set (a JSON object, or a compact JWT whose payload is one).

    Succeeds on a well-formed GitHub claim set. Success means "this IS a claim set", NOT
    "this is who ran the build" — the returned data says so in two explicit fields, and
    `establishes_identity()` says it again in code.
    """
    reg = registry or shapes.registry()
    res, text = C.decode_text(raw, SHAPE_CLAIMS)
    if res is not None:
        return res
    text = text.strip()

    if text.startswith("{"):
        claims_res, claims = C.load_json(text, SHAPE_CLAIMS)
        if claims_res is not None:
            return claims_res
    else:
        claims_res, claims = _decode_jwt_payload(text)
        if claims_res is not None:
            return claims_res

    if not isinstance(claims, dict):
        return C.unknown(SHAPE_CLAIMS, "claim set is not a JSON object")
    missing = [c for c in REQUIRED_CLAIMS if c not in claims]
    if missing:
        return C.unknown(SHAPE_CLAIMS, f"claim set is missing required claims: {missing}")
    if claims.get("iss") != GITHUB_ISSUER:
        return C.fail(SHAPE_CLAIMS, R.AUT_IDENTITY_NOT_PERMITTED,
                      f"issuer {claims.get('iss')!r} is not {GITHUB_ISSUER!r}", data=claims)

    good, code, detail = shapes.validate_shape(claims, SHAPE_CLAIMS, reg)
    if not good:
        return C.fail(SHAPE_CLAIMS, code, detail, data=claims)

    exp, iat = claims["exp"], claims["iat"]
    nbf = claims.get("nbf", iat)
    if not isinstance(nbf, int) or isinstance(nbf, bool):
        return C.unknown(SHAPE_CLAIMS, f"nbf claim {nbf!r} is not an integer")
    if exp <= iat:
        return C.unknown(SHAPE_CLAIMS, f"token exp {exp} is not after iat {iat}")
    if nbf > exp:
        return C.unknown(SHAPE_CLAIMS, f"token nbf {nbf} is after its own exp {exp}")

    return C.ok(SHAPE_CLAIMS, {
        "claims": dict(claims),
        "context": context_from_claims(claims),
        "repository": claims["repository"],
        "issuedAt": iat,
        "notBefore": nbf,
        "expiresAt": exp,
        "signatureVerified": False,
        "identityEstablished": False,
        "note": UNVERIFIED_JWT_DETAIL,
    })


def establishes_identity(parsed=None):
    """(False, reason_code, detail) — unconditionally.

    A function rather than a comment, so "claims are not identity" is a rule code CALLS
    rather than one a future reader is trusted to remember.
    """
    suffix = ""
    if isinstance(parsed, dict) and parsed.get("repository"):
        suffix = (f" (a claim set for {parsed['repository']!r} was parsed and is available as "
                  "corroboration)")
    return False, R.AUT_IDENTITY_NOT_ESTABLISHED, UNVERIFIED_JWT_DETAIL + suffix


def _decode_jwt_payload(token):
    parts = token.split(".")
    if len(parts) != 3:
        return C.unknown(SHAPE_CLAIMS,
                         f"expected a JSON object or a 3-part compact JWT, got {len(parts)} "
                         "parts"), None
    payload = parts[1]
    pad = "=" * (-len(payload) % 4)
    raw = payload.replace("-", "+").replace("_", "/") + pad
    res, decoded = C.b64decode_strict(raw, "JWT payload", SHAPE_CLAIMS)
    if res is not None:
        return res, None
    return C.load_json(decoded, SHAPE_CLAIMS)


def check_claims(claims, expected_repository=None, expected_sha=None, expected_audience=None,
                 at_time=None, require_github_hosted=True):
    """Check a claim set against what the decision says the subject is.

    Returns (ok, reason_code, detail). `ok=True` means "nothing here contradicts the subject,
    and the token was live at `at_time`". It does NOT mean identity — that question goes
    through `establishes_identity`, which always says no.

    `at_time` is the moment the token needs to have been valid AT: pass the Rekor
    `integratedTime` when judging a recorded claim set against the signature it accompanied,
    or leave it None to judge a live token against the wall clock.
    """
    if not isinstance(claims, dict):
        return False, R.AUT_OUTPUT_SHAPE_UNKNOWN, "claim set is not an object"

    if claims.get("iss") != GITHUB_ISSUER:
        return (False, R.AUT_IDENTITY_NOT_PERMITTED,
                f"issuer {claims.get('iss')!r} is not {GITHUB_ISSUER!r}")

    if expected_audience is not None and claims.get("aud") != expected_audience:
        return (False, R.AUT_IDENTITY_NOT_PERMITTED,
                f"audience {claims.get('aud')!r} is not the required {expected_audience!r}; "
                "a token minted for another audience must not be replayed here")

    if expected_repository is not None:
        got = str(claims.get("repository", ""))
        if got.lower() != str(expected_repository).strip().lower():
            return (False, R.AUT_BINDING_MISMATCH,
                    f"token repository claim {got!r} is not the decision's subject "
                    f"{expected_repository!r}")

    if expected_sha is not None and claims.get("sha") != expected_sha:
        return (False, R.AUT_BINDING_MISMATCH,
                f"token sha claim {str(claims.get('sha'))[:12]}… is not the decision's commit "
                f"{str(expected_sha)[:12]}…")

    if require_github_hosted and claims.get("runner_environment") != "github-hosted":
        return (False, R.AUT_IDENTITY_NOT_PERMITTED,
                f"runner_environment is {claims.get('runner_environment')!r}; a self-hosted "
                "runner is machinery the builder controls, so it cannot vouch for the builder")

    exp, iat = claims.get("exp"), claims.get("iat")
    nbf = claims.get("nbf", iat)
    for label, value in (("exp", exp), ("iat", iat), ("nbf", nbf)):
        if not isinstance(value, int) or isinstance(value, bool):
            return False, R.AUT_OUTPUT_SHAPE_UNKNOWN, f"{label} claim is not an integer"
    reference = at_time if at_time is not None else _now_epoch()
    if reference >= exp:
        return (False, R.AUT_FRESHNESS_EXPIRED,
                f"the token had already expired {reference - exp}s before the moment it is "
                f"judged at (exp={exp}, reference={reference})")
    if reference < nbf:
        return (False, R.AUT_FRESHNESS_EXPIRED,
                f"the token was not yet valid at the moment it is judged at "
                f"({nbf - reference}s early; nbf={nbf}, reference={reference})")

    return True, None, (f"claim set is internally consistent and was live at {reference}; "
                        "still not identity — see establishes_identity()")


def context_from_claims(claims):
    """The auditable, NON-identity context worth recording in an attestation's detail."""
    if not isinstance(claims, dict):
        return {}
    keep = ("repository", "repository_id", "repository_owner", "repository_owner_id",
            "repository_visibility", "workflow_ref", "job_workflow_ref", "ref", "sha",
            "run_id", "run_attempt", "runner_environment", "environment", "event_name",
            "actor_id", "aud")
    ctx = {k: claims[k] for k in keep if k in claims}
    ctx["signatureVerified"] = False
    ctx["identityEstablished"] = False
    return ctx


def _now_epoch():
    import datetime as dt
    return int(dt.datetime.now(dt.timezone.utc).timestamp())


__all__ = [
    "GITHUB_ISSUER", "REQUIRED_CLAIMS", "SHAPE_CLAIMS", "UNVERIFIED_JWT_DETAIL",
    "check_claims", "context_from_claims", "establishes_identity", "parse_claims",
]
