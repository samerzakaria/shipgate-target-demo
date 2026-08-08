"""Live observation, and the binding that makes an observation about THIS decision.

THE FINDING THIS ANSWERS. `GithubEnvironmentPrincipalVerifier` read a JSON file whose path the
operator supplied and, if its fields looked right, established the `principal` fact — the claim
that somebody the builder cannot impersonate had to act. `principal` is the entire difference
between CI_ATTESTED and INDEPENDENTLY_ATTESTED, so the strongest claim this product can make
rested on a file written by the party seeking the award. Six edits to a capture that ships
inside the skill were enough.

THE FIX IS NOT A BETTER FILE FORMAT. There is no shape a file can have that makes it
authentic, and every schema added to check one is a more convincing way to be wrong. Either
the verifier looked at GitHub itself or it did not. So: the principal fact may ONLY come from
an observation this module made, over TLS, at verification time. `gh.environment` as a source
of `principal` is dead, and reading one is a refusal that says why.

WHY THIS IS A SEPARATE MODULE. The kit's default path makes no network call and spawns no
subprocess; `tests/boundary/test_import_boundary.py` enforces it, and it is why the subsystem
runs in an air-gapped container and can be deleted wholesale. Live observation genuinely needs
the network, so it lives here, is imported only when an operator explicitly asks for it, and
its absence is a refusal rather than a fallback. Nothing in the offline path imports this file.

WHAT AN OBSERVATION IS WORTH, stated before anyone quotes it:

  * It proves what GitHub's API said to THIS process at THIS moment over TLS. It does not
    prove GitHub is honest, that the token was not over-scoped, or that the protection rules
    were in force when the build ran rather than when the check ran.
  * A read token cannot change what GitHub reports, which is the property being relied on. An
    operator holding a token can read; they cannot make the API describe reviewers who do not
    exist. That is the whole difference from a file.
  * `TOKEN IS A CREDENTIAL, NOT A CLAIM.` Supplying a token is fine. Supplying the ANSWER is
    what was wrong.
"""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

GITHUB_API = "https://api.github.com"
USER_AGENT = "shipgate-authority-verifier/4.2"
TIMEOUT_SECONDS = 20

#: Environment variables a token may come from, in order. Deliberately NOT a config key: a
#: token written into an authority config gets committed, and a credential in a repository is
#: a worse failure than the one this module fixes.
TOKEN_ENV = ("SHIPGATE_VERIFIER_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")

#: OIDC issuers whose certificates this kit will accept as EXTERNAL evidence of who a
#: verifier is. Pinned in code and deliberately not widenable by configuration, for the same
#: reason `GithubOidcIdentityVerifier` lets an operator pin an issuer and never widen one: a
#: trust root a config file can add to is not a trust root.
AUTHORIZED_ISSUERS = (
    "https://token.actions.githubusercontent.com",
    "https://accounts.google.com",
    "https://oauth2.sigstore.dev/auth",
    "https://token.actions.githubusercontent.com/",
)

#: Where the list of verifiers permitted to confer independence comes from. An ENVIRONMENT
#: VARIABLE on the verifier's own process, never the authority config — the config file lives
#: in the repository being judged, so a repository could otherwise authorise itself.
AUTHORIZED_VERIFIERS_ENV = "SHIPGATE_AUTHORIZED_VERIFIERS"


def authorized_verifiers():
    """Identities allowed to confer INDEPENDENTLY_ATTESTED, from outside the target."""
    raw = os.environ.get(AUTHORIZED_VERIFIERS_ENV, "")
    return tuple(x.strip() for x in raw.replace(";", ",").split(",") if x.strip())


class LiveObservationError(Exception):
    """The observation could not be made. ALWAYS a refusal, never a fallback to a file."""


class Blocked(LiveObservationError):
    """The observation is impossible in this environment, and that is reportable as BLOCKED.

    Distinct from a failed observation on purpose. "I could not reach GitHub" and "GitHub says
    this environment has no reviewers" must never collapse into one outcome — the first is an
    unknown and the second is a finding, and a gate that reports an unknown as a finding is as
    broken as one that reports it as a pass.
    """


def token(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    for name in TOKEN_ENV:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


def available(explicit_token: Optional[str] = None):
    """(usable, detail). Never raises, so `doctor` can report it without a network call."""
    if not token(explicit_token):
        return False, ("no verifier token in "
                       f"{', '.join(TOKEN_ENV)}; live observation of GitHub is impossible, so "
                       "the principal fact is BLOCKED rather than read from a file")
    return True, "a verifier token is present; GitHub state will be observed over TLS"


def _get(url: str, tok: str) -> Dict[str, Any]:
    """One authenticated GET. Returns the decoded body plus what was observed about it."""
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {tok}",
    })
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read()
            status = response.status
            served_by = response.headers.get("X-GitHub-Request-Id", "")
            api_date = response.headers.get("Date", "")
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:400].decode("utf-8", "replace")
        if exc.code in (401, 403):
            raise Blocked(
                f"GitHub refused the verifier token for {url} (HTTP {exc.code}). Without read "
                f"access the principal cannot be observed, and an unobserved principal is "
                f"BLOCKED, never assumed: {detail}")
        if exc.code == 404:
            raise LiveObservationError(
                f"GitHub reports {url} does not exist or is not visible to this token "
                f"(HTTP 404). A configured environment the verifier cannot see is a refusal.")
        raise LiveObservationError(f"GitHub returned HTTP {exc.code} for {url}: {detail}")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise Blocked(f"GitHub is unreachable from this verifier ({type(exc).__name__}: "
                      f"{exc}); the principal is BLOCKED, not assumed")

    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise LiveObservationError(f"GitHub returned a body that is not JSON: {exc}")

    return {
        "url": url,
        "httpStatus": status,
        "requestId": served_by,
        "apiDate": api_date,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        # THE RAW BYTES ARE THE RECORD. `body` below is a convenience for humans and for
        # the live path; on the two-phase path the parsed body is rebuilt from THIS, because
        # a digest over bytes nobody kept cannot be rechecked. Storing the parse and the
        # digest independently is what let a swapped body keep a valid signature.
        "bodyB64": base64.b64encode(body).decode("ascii"),
        "elapsedSeconds": round(time.time() - started, 3),
        "body": parsed,
    }


def observe_environment(owner_repo: str, environment: str,
                        explicit_token: Optional[str] = None,
                        fetch=None, run_id: str = "",
                        commit: str = "") -> Dict[str, Any]:
    """Observe a repository, one deployment environment and — v4.2 — this run's passage.

    Returns ALL raw observations. The repository is fetched too, and not for decoration: the
    builder's own permissions are what decide whether a reviewer is a distinct principal, and
    reading them from the same live source closes the gap where an operator supplied a
    flattering `repo.json` next to a flattering `environment.json`.

    When `run_id` (and ideally `commit`) are supplied, four more observations are attempted —
    the workflow run, the environment's deployments for this commit, the first matching
    deployment's statuses, and the run's approvals — because independence requires PASSAGE
    through the gate, not the gate's existence. A part that cannot be fetched is recorded as
    unavailable rather than killing the whole observation: environment evidence still
    supports lower tiers, and the absent part will refuse independence downstream on its own.
    """
    getter = fetch or _get
    tok = token(explicit_token)
    if not tok:
        raise Blocked(available(explicit_token)[1])
    if "/" not in owner_repo:
        raise LiveObservationError(f"{owner_repo!r} is not an owner/repo pair")

    repo = getter(f"{GITHUB_API}/repos/{owner_repo}", tok)
    env = getter(f"{GITHUB_API}/repos/{owner_repo}/environments/{environment}", tok)
    observation = {
        "observedAt": int(time.time()),
        "observer": USER_AGENT,
        "repository": repo,
        "environment": env,
    }
    if run_id:
        def attempt(name, url):
            try:
                observation[name] = getter(url, tok)
            except LiveObservationError as exc:
                observation[name] = {"unavailable": str(exc), "url": url}
        attempt("run", f"{GITHUB_API}/repos/{owner_repo}/actions/runs/{run_id}")
        deploy_url = (f"{GITHUB_API}/repos/{owner_repo}/deployments"
                      f"?environment={environment}" + (f"&sha={commit}" if commit else ""))
        attempt("deployments", deploy_url)
        deployments = observation.get("deployments") or {}
        body = deployments.get("body")
        if isinstance(body, list) and body and isinstance(body[0], dict) \
                and body[0].get("id") is not None:
            attempt("deploymentStatuses",
                    f"{GITHUB_API}/repos/{owner_repo}/deployments/{body[0]['id']}/statuses")
        attempt("approvals",
                f"{GITHUB_API}/repos/{owner_repo}/actions/runs/{run_id}/approvals")
    return observation


def bind(observation: Dict[str, Any], decision, external_time: Optional[int] = None,
         run_id: str = "", run_attempt: str = "", verifier_identity: str = "",
         verifier_identity_verified: bool = False,
         verifier_authorized: bool = False,
         policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Tie an observation to THIS decision, this commit, this run and an external clock.

    An unbound observation is a screenshot: true of something, at some time, about some
    repository. Four things make it evidence about this release —

      decisionDigest   the observation cannot be replayed onto a different decision
      commit           it is about the tree that was judged
      runId            it belongs to this run rather than a previous green one
      externalTime     `observedAt` is the verifier's own clock, which the verifier controls;
                       the external time comes from the Rekor checkpoint verified against the
                       pinned key, so a verifier lying about when it looked is detectable

    `verifierIdentity` is carried so `contracts.evaluate` can refuse an attestation where the
    observer and the builder are the same principal. It is recorded here and judged there,
    because this module must not be in the business of awarding anything.
    """
    digest = decision.digest() if hasattr(decision, "digest") else str(decision)
    subject = getattr(decision, "subject", None)
    payload = {
        "decisionDigest": digest,
        "commit": getattr(subject, "commit", "") or "",
        "repository": getattr(subject, "repository", "") or "",
        "runId": run_id,
        "runAttempt": run_attempt,
        # NEVER defaults to USER_AGENT. It used to, and that made the producer-is-not-the-
        # verifier rule vacuous: a constant string can never equal a builder's subject, so the
        # check passed for everyone including a builder attesting their own release. An
        # unauthenticated identity is recorded as empty and refused downstream.
        "verifierIdentity": verifier_identity or "",
        "verifierIdentityVerified": bool(verifier_identity_verified
                                         and verifier_identity),
        # SEPARATE from `verifierIdentityVerified`, because they answer different questions:
        # one is "did this verifier sign this observation", the other is "who authorised this
        # verifier to confer anything". Only the second gates independence.
        "verifierAuthorized": bool(verifier_authorized and verifier_identity_verified
                                   and verifier_identity),
        "observedAt": observation.get("observedAt"),
        "externalTime": external_time,
        "repositoryBodySha256": (observation.get("repository") or {}).get("bodySha256"),
        "environmentBodySha256": (observation.get("environment") or {}).get("bodySha256"),
        # WHAT WAS OBSERVED, carried for the one enforcement site. The environment name and
        # the numeric repository id come out of the OBSERVED response bodies — the same bytes
        # the body digests above cover — never out of configuration.
        "environment": ((observation.get("environment") or {}).get("body") or {}).get("name"),
        "repositoryId": ((observation.get("repository") or {}).get("body") or {}).get("id"),
    }
    if policy is not None:
        # The VERIFIED policy record rides in the binding so `enforcement.enforce_award` can
        # judge every field where all facts are visible. This is a record of a verification
        # that already happened against the pinned root — not a policy the operator typed.
        payload["policy"] = {
            "repository": policy.get("repository"),
            "repositoryId": policy.get("repositoryId"),
            "version": policy.get("version"),
            "authorizedBuilders": list(policy.get("authorizedBuilders") or ()),
            "authorizedVerifiers": list(policy.get("authorizedVerifiers") or ()),
            "requiredEnvironment": policy.get("requiredEnvironment"),
            "notBefore": policy.get("notBefore"),
            "notAfter": policy.get("notAfter"),
            "policyDigest": policy.get("policyDigest"),
            "rollbackChecked": bool(policy.get("rollbackChecked")),
            "highestSeenVersion": policy.get("highestSeenVersion"),
        }
    if not payload["verifierIdentityVerified"]:
        payload["verifierIdentityNote"] = (
            "no signed verifier identity was presented, so who performed this observation is "
            "unknown. Independence cannot be awarded to an anonymous observer.")
    if external_time is None:
        payload["externalTimeNote"] = (
            "no verified external timestamp was supplied, so `observedAt` is the verifier's "
            "own unverified clock")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["bindingDigest"] = hashlib.sha256(canonical).hexdigest()
    return payload


def describe() -> str:
    return "\n".join([
        "LIVE OBSERVATION — the principal fact's only legal source.",
        "",
        "  A deployment environment's protection rules are read from api.github.com over TLS",
        "  at verification time. An operator-supplied JSON record is REFUSED: there is no",
        "  shape a file can have that makes it authentic.",
        "",
        f"  Token from {', '.join(TOKEN_ENV)} — never from the authority config, because a",
        "  token written into a config gets committed.",
        "",
        "  NOT proved: that GitHub is honest, that the token is correctly scoped, or that the",
        "  rules were in force when the BUILD ran rather than when the CHECK ran. What is",
        "  proved is that a read-only token cannot make the API describe reviewers who do not",
        "  exist, which is the entire difference from a file.",
    ])


# =======================================================================================
# who verified — proved by signature, never asserted
# =======================================================================================


def binding_challenge(observation: Dict[str, Any], decision, run_id: str = "",
                      external_time: Optional[int] = None) -> bytes:
    """The exact bytes a verifier must sign to claim it made THIS observation.

    Signing happens over a challenge rather than over the finished binding because the
    binding records WHO signed, and a payload cannot contain the answer to the question it
    is being used to settle.

    WHAT THE CHALLENGE COVERS, AND THE LIMIT OF IT. Decision digest, commit, repository and
    run id — everything that identifies WHICH release is being vouched for, and all of it
    knowable before the observation happens. A signature over this cannot be replayed onto a
    different decision, a different commit or a different run.

    It deliberately does NOT cover the observed response bodies or the observation timestamp,
    and that is a real limit rather than an oversight. Those values do not exist until the
    verifier has already looked, so requiring them would mean the signer had to sign
    something it could only learn by being the same process that observes — which is exactly
    the deployment this supports, but not one a pre-supplied bundle can satisfy. The
    consequence, stated plainly: the signature proves WHO vouched for this decision, and the
    observation is tied to that identity by having happened in the same verifier run, not by
    a second signature over the response bodies. Closing that last gap needs the verifier to
    sign after observing, which is a deployment change and not a code change here.
    """
    subject = getattr(decision, "subject", None)
    payload = {
        "schema": "shipgate.authority.verifier-challenge/1",
        "decisionDigest": decision.digest() if hasattr(decision, "digest") else str(decision),
        "commit": getattr(subject, "commit", "") or "",
        "repository": getattr(subject, "repository", "") or "",
        "runId": run_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_verifier_identity(challenge: bytes, verifier_config: Dict[str, Any],
                             resolve=None):
    """(identity, verified, authorized, detail, policy_record) — TWO questions, separately.

    An external reviewer put the distinction better than the original code did:

      BINDING        did this verifier sign this exact observation?
      AUTHORIZATION  who externally authorised this verifier to confer independence?

    v4.2: the loaded external policy record travels back as the fifth element (None when no
    policy was verifiable), because the FULL policy enforcement — authorizedBuilders, the
    required environment, the validity window, the rollback requirement — happens where every
    fact is visible at once: `enforcement.enforce_award`, called from `contracts.evaluate`.
    This function answers only the two questions above; `authorized` here is the verifier-
    membership half, and it is necessary but no longer sufficient for independence.

    The first version proved binding and called it authorisation. A cosign signature under an
    operator-supplied public key genuinely proves the holder signed — and proves nothing
    about who they are, because `cosign generate-key-pair` makes a verifier out of anybody.
    A self-issued key is its own source of authority, which is not a source of authority.

    So `verified` and `authorized` are now different booleans and the caller keeps both. A
    keyed signature is honestly reported as bound-but-unauthorised: it reaches CI_ATTESTED
    and stops. Independence additionally needs a Fulcio identity from a PINNED issuer,
    present on a list supplied to the verifier's own process.

    The verifier presents a cosign signature over the challenge. cosign is RUN — the same
    rule as everywhere else in v4.1 — and the identity comes out of the constraint cosign was
    given, not out of a config field the operator typed. A keyed signature yields the public
    key's digest as the identity, which is a real cryptographic identity; a keyless one yields
    the certificate subject.

    Returns verified=False rather than raising, because "nobody proved who they are" is a
    normal outcome that must read as BLOCKED downstream, not as a crash.
    """
    if not isinstance(verifier_config, dict) or not verifier_config:
        return "", False, False, ("no `verifier` section: nothing proves who performed "
                                  "this observation, so independence is BLOCKED"), None

    # BINDING IS NOT AUTHORIZATION, and this kit previously treated them as one thing.
    #
    # A cosign signature under an operator-supplied PUBLIC KEY proves that whoever holds that
    # key signed this observation. It does not answer the question the word "independent"
    # asks, because the operator generated the key. `cosign generate-key-pair` makes a
    # verifier out of anybody in one command, and the result was a self-authorising loop
    # dressed as a cryptographic check.
    #
    # So a keyed signature can no longer confer independence. Two things are required, and
    # they answer two different questions:
    #
    #   WHO   a Fulcio certificate, so an OIDC provider outside this system asserts the
    #         identity. The issuer must be one this kit pins.
    #   WHY   that identity must appear on a list supplied to the VERIFIER's process, not
    #         read from the authority config — which lives in the repository under judgement.
    #
    # What this cannot do is invent an authority. Who belongs on the list is an
    # organisational decision, and no code makes it. What it can do is stop the target from
    # answering the question about itself.
    issuer = verifier_config.get("certificateOidcIssuer")
    identity = verifier_config.get("certificateIdentity")
    if identity and issuer not in AUTHORIZED_ISSUERS:
        return "", False, False, (
            f"OIDC issuer {issuer!r} is not one this kit accepts as external evidence of a "
            f"verifier's identity. Accepted: {', '.join(sorted(set(AUTHORIZED_ISSUERS)))}. "
            f"This list is pinned in code and cannot be widened by configuration."), None

    allowed = authorized_verifiers()
    policy_record = None
    resolve = resolve or (lambda key: verifier_config.get(key))
    bundle = resolve("bundle")
    if not bundle:
        return "", False, False, ("verifier.bundle is not configured; the observer signed "
                                  "nothing"), None
    try:
        from . import cosignexec
    except ImportError as exc:  # pragma: no cover
        return "", False, False, f"cosign runner unavailable: {exc}", None

    import tempfile
    key_path = resolve("publicKey")
    identity = verifier_config.get("certificateIdentity")
    issuer = verifier_config.get("certificateOidcIssuer")
    tmp = tempfile.NamedTemporaryFile(prefix="shipgate-challenge-", delete=False)
    try:
        tmp.write(challenge)
        tmp.close()
        result = cosignexec.verify_blob(tmp.name, bundle, key_path=key_path,
                                        certificate_identity=identity,
                                        certificate_oidc_issuer=issuer)
    except cosignexec.CosignExecError as exc:
        return ("", False, False,
                f"the verifier's own signature could not be checked: {exc}", None)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    if not result["verified"]:
        return "", False, False, (f"the verifier's signature over its own observation did "
                                  f"NOT verify: {result['detail']}"), None
    if not identity:
        # KEYED. The signature is real; the identity behind it is a key digest, which proves
        # possession and nothing more. It stops at CI_ATTESTED — UNLESS the externally signed
        # policy itself pins this exact `key:` string, in which case the policy root, not the
        # key holder, is the source of the authorisation.
        import hashlib
        try:
            with open(key_path, "rb") as fh:
                who = "key:" + hashlib.sha256(fh.read()).hexdigest()[:32]
        except OSError:
            return "", False, False, "the verifier public key became unreadable mid-check", None
    else:
        who = identity

    # AUTHORIZATION COMES FROM THE EXTERNAL POLICY. The environment allowlist below it is a
    # convenience for operators running their own verifier, and it is deliberately NOT
    # sufficient for independence: an environment variable is set by whoever launches the
    # process, which in a self-hosted pipeline is the same party being judged.
    from . import policy as policy_module
    repository = str(verifier_config.get("_repository") or "")
    try:
        policy_record = policy_module.load(repository)
    except policy_module.NoPolicy as exc:
        if not identity:
            return who, True, False, (
                f"the observation is BOUND to {who} — that key signed it — but the key is "
                f"self-issued, so nothing external authorises its holder to confer "
                f"independence. Binding without authorisation stops at CI_ATTESTED."), None
        return who, True, False, (
            f"BOUND to {who!r}, NOT AUTHORISED: {exc}"), None
    except policy_module.PolicyError as exc:
        return who, True, False, (
            f"BOUND to {who!r}, NOT AUTHORISED: the external policy was refused "
            f"({exc})"), None

    ok, why = policy_module.authorizes_verifier(policy_record, who)
    if not ok:
        if not identity:
            return who, True, False, (
                f"the observation is BOUND to {who} — that key signed it — but the key is "
                f"self-issued and the external policy does not pin it, so nothing external "
                f"authorises its holder to confer independence. Binding without "
                f"authorisation stops at CI_ATTESTED."), policy_record
        return who, True, False, f"BOUND to {who!r}, NOT AUTHORISED: {why}", policy_record
    if allowed and who not in allowed:
        return who, True, False, (
            f"the external policy authorises {who!r} but {AUTHORIZED_VERIFIERS_ENV} "
            f"does not; two sources of authorisation that disagree are not two "
            f"authorisations"), policy_record
    asserted_by = (issuer if identity else
                   f"the pinned policy root (an explicit key pin, "
                   f"signed by {(policy_record.get('signature') or {}).get('signedBy')!r})")
    return who, True, True, (
        f"{who!r} signed this observation, {asserted_by} asserts that identity, and policy "
        f"version {policy_record['version']} for {policy_record['repository']} authorises "
        f"it (policy digest {policy_record['policyDigest'][:16]}…)"), policy_record


# =======================================================================================
# two-phase: observe, sign what was observed, then verify that
# =======================================================================================

OBSERVATION_SCHEMA = "shipgate.authority.observation/1"


def observation_challenge(observation: Dict[str, Any], decision, run_id: str = "",
                          external_time: Optional[int] = None,
                          run_attempt: str = "") -> bytes:
    """The FULL challenge — everything in `binding_challenge`, plus what was actually seen.

    This is the one `binding_challenge` could not be. A verifier cannot sign response-body
    digests before it has made the request, so the single-phase flow signs only the release
    identity and the observation rides along on trust that the same process made it.

    Two-phase removes that. Phase 1 observes and writes the observation down. The verifier
    signs THIS challenge, which commits to the exact bytes GitHub returned. Phase 2 verifies
    the signature and then uses the recorded observation — which is safe precisely because
    editing any part of it changes a digest the signature covers.

    That is why a persisted observation is not the file this kit refuses. The refused file was
    unauthenticated; this one carries a signature over its own contents.
    """
    payload = json.loads(binding_challenge(observation, decision, run_id, external_time))
    # /2, deliberately: v4.2 widened what the signature commits to (numeric repository id,
    # environment name, artifact digest, run attempt, and the deployment-evidence response
    # digests), so a v4.1 signature cannot be replayed as though it covered them. An old
    # recording therefore refuses under this build — re-record with `gate.py observe`. That
    # is the correct failure: a signature must never be read as covering more than it signed.
    payload["schema"] = "shipgate.authority.observation-challenge/2"
    payload["observedAt"] = observation.get("observedAt")
    payload["externalTime"] = external_time
    payload["runAttempt"] = run_attempt
    subject = getattr(decision, "subject", None)
    payload["artifactDigest"] = getattr(subject, "artifact_digest", None) or ""
    payload["repositoryId"] = ((observation.get("repository") or {}).get("body")
                               or {}).get("id")
    payload["environment"] = ((observation.get("environment") or {}).get("body")
                              or {}).get("name")
    for name, key in (("repository", "repositoryBodySha256"),
                      ("environment", "environmentBodySha256"),
                      ("run", "runBodySha256"),
                      ("deployments", "deploymentsBodySha256"),
                      ("deploymentStatuses", "deploymentStatusesBodySha256"),
                      ("approvals", "approvalsBodySha256")):
        part = observation.get(name) or {}
        payload[key] = part.get("bodySha256")
    payload["repositoryUrl"] = (observation.get("repository") or {}).get("url")
    payload["environmentUrl"] = (observation.get("environment") or {}).get("url")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_observation(observation: Dict[str, Any], decision, path: str, run_id: str = "",
                      external_time: Optional[int] = None,
                      run_attempt: str = "") -> Dict[str, Any]:
    """Persist phase 1. Returns {observationPath, challengePath, challengeSha256}."""
    challenge = observation_challenge(observation, decision, run_id, external_time,
                                      run_attempt)
    document = {
        "schema": OBSERVATION_SCHEMA,
        "observation": observation,
        "runId": run_id,
        "runAttempt": run_attempt,
        "externalTime": external_time,
        "challengeSha256": hashlib.sha256(challenge).hexdigest(),
    }
    base = os.path.splitext(path)[0]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
    challenge_path = base + ".challenge"
    with open(challenge_path, "wb") as fh:
        fh.write(challenge)
    return {"observationPath": path, "challengePath": challenge_path,
            "challengeSha256": document["challengeSha256"]}


def load_observation(path: str, decision, run_id: str = "",
                     external_time: Optional[int] = None,
                     run_attempt: str = ""):
    """(observation, challenge). Rebuilds the challenge FROM the file, never trusting the
    digest recorded inside it — a self-reported digest is not a check."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, ValueError) as exc:
        raise LiveObservationError(f"recorded observation {path} is unreadable: {exc}")
    if not isinstance(document, dict) or document.get("schema") != OBSERVATION_SCHEMA:
        raise LiveObservationError(
            f"{path} is not a {OBSERVATION_SCHEMA} document")
    observation = document.get("observation")
    if not isinstance(observation, dict):
        raise LiveObservationError(f"{path} carries no observation")

    # RECOMPUTE THE DIGESTS, AND REBUILD THE BODY FROM THE BYTES THEY COVER.
    #
    # This is the defect an external reviewer predicted before running anything, and it was
    # real: the signed challenge carried the observation's STORED `bodySha256`, and nothing
    # checked that digest against the stored body. Swapping the body while leaving the digest
    # alone therefore left the challenge — and so the signature — completely valid. A weak
    # environment could be signed honestly and then edited into a qualifying one.
    #
    # The digest is over the raw response bytes, and a parsed-then-reserialised body cannot
    # reproduce them, so the raw bytes are what is kept and what is re-read here. Any stored
    # `body` is DISCARDED and reparsed from the digest-covered bytes: leaving it in place as
    # a fallback would be the same hole with an extra step.
    # The repository and environment parts are REQUIRED; the v4.2 deployment parts (run,
    # deployments, statuses, approvals) are verified whenever present — a part that carries
    # a body digest is a part the challenge covers, so its bytes get exactly the same
    # recompute-and-compare treatment. A part recorded as {"unavailable": ...} carries no
    # digest and is skipped: absence is honest and refuses independence downstream.
    optional_parts = [name for name in ("run", "deployments", "deploymentStatuses",
                                        "approvals")
                      if isinstance(observation.get(name), dict)
                      and observation[name].get("bodySha256")]
    for name in ["repository", "environment"] + optional_parts:
        part = observation.get(name)
        if not isinstance(part, dict):
            raise LiveObservationError(f"{path} has no {name} observation")
        raw_b64 = part.get("bodyB64")
        if not raw_b64:
            raise LiveObservationError(
                f"the {name} observation in {path} carries no bodyB64, so its digest covers "
                f"bytes nobody kept and the body cannot be re-verified. Re-record it with "
                f"`gate.py observe` from this version.")
        try:
            raw = base64.b64decode(raw_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise LiveObservationError(f"{name} bodyB64 is not valid base64: {exc}")
        recomputed = hashlib.sha256(raw).hexdigest()
        if recomputed != part.get("bodySha256"):
            raise LiveObservationError(
                f"BODY_DIGEST_MISMATCH: the {name} observation's recorded digest "
                f"{part.get('bodySha256')} does not match its stored bytes ({recomputed}); "
                f"the recording has been edited")
        try:
            reparsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise LiveObservationError(f"{name} body is not JSON: {exc}")
        # A stored parse that disagrees with the bytes is a CONTRADICTION, not something to
        # quietly overrule. Silently preferring the bytes would leave a file on disk saying
        # one thing while the kit acted on another — which is how a reader gets misled even
        # when the decision is correct.
        stored = part.get("body")
        if stored is not None and stored != reparsed:
            raise LiveObservationError(
                f"BODY_DIGEST_MISMATCH: the {name} observation's stored body does not "
                f"match its own recorded bytes; the recording has been edited")
        part["body"] = reparsed
    # A CONTRADICTION IS A REFUSAL, not a preference. The caller's run id used to win
    # silently, which made the recorded one decorative: an observation could be moved to a
    # different run by editing a field nothing read. Two sources that disagree are not two
    # pieces of evidence — the same rule this kit applies to rekor-cli versus the REST entry.
    recorded_run = str(document.get("runId") or "")
    if run_id and recorded_run and run_id != recorded_run:
        raise LiveObservationError(
            f"the recorded observation belongs to run {recorded_run!r} but this attestation "
            f"is for run {run_id!r}; an observation from another run is not evidence about "
            f"this one")
    recorded_attempt = str(document.get("runAttempt") or "")
    if run_attempt and recorded_attempt and run_attempt != recorded_attempt:
        raise LiveObservationError(
            f"the recorded observation belongs to run attempt {recorded_attempt!r} but this "
            f"attestation is for attempt {run_attempt!r}; a rerun is a different execution "
            f"and its observation is not evidence about this one")
    recorded_time = document.get("externalTime")
    if (external_time is not None and recorded_time is not None
            and external_time != recorded_time):
        raise LiveObservationError(
            f"the recorded observation carries external time {recorded_time} but this "
            f"attestation was given {external_time}; they cannot both be true")

    # Recomputed, not read. The `challengeSha256` inside the file is a convenience for a
    # human; using it to decide anything would let the file vouch for itself.
    challenge = observation_challenge(
        observation, decision,
        run_id or recorded_run,
        external_time if external_time is not None else recorded_time,
        run_attempt or recorded_attempt)
    return observation, challenge
