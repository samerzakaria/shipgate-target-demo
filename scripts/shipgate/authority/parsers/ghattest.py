"""`gh attestation verify --format json` parsing: GitHub's verified attestation, as facts.

WHAT THE INPUT IS. The machine output of GitHub's OWN verifier, produced by a subprocess this
kit just ran (`ghexec.verify_attestation`) — never a file an operator supplied. gh has already
checked the certificate chain to the Sigstore/GitHub roots, the SCT, the transparency-log
proof and the artifact digest against the in-toto subject; this parser's job is narrower and
different: establish that the output has the ONE validated shape, then CROSS-CHECK everything
in it against the decision under judgement. gh proves the attestation is real; this module
proves it is about THIS release.

THE CAPTURE BEHIND THE SHAPE. `gh_attestation_verify_ok.json` is a REAL verification: the
npm package `@sigstore/verify@4.1.2` (published 2026-08-04 with npm provenance), attested by
`sigstore/sigstore-js`'s release workflow on GitHub-hosted runners, verified fully offline by
gh v2.97.0 against the attestation bundle served by the npm registry and the Sigstore TUF
trusted root. Nothing in it is sanitised: the certificate names a real repository (id
495574555), a real commit, a real run. PROVENANCE_gh_attestation.txt in the corpus records
the exact procedure.

WHAT A VERIFIED ATTESTATION ESTABLISHES, and the limits, stated before anyone quotes it:

  identity   the builder workflow identity (certificate SAN) as asserted by GitHub's OIDC
             issuer and bound into a Fulcio certificate that gh verified — plus the numeric
             repository and owner ids, which survive renames.
  binding    to the ARTIFACT (digest), the commit, the repository, and the workflow run —
             not to the decision digest. The decision references the artifact through
             `subject.artifactDigest`; the cross-check below is what ties the two, and a
             decision that carries no artifact digest gets NO binding fact from this path.
  freshness  the transparency-log timestamp gh verified (`verifiedTimestamps`), an external
             clock suitable for the policy validity window.

  NOT established: that the workflow did what its name suggests, that the run was reviewed,
  or that anyone independent looked. This is CI evidence — the principal axis is untouched.
"""
import datetime
import re

from ...models import reasons as R
from .. import shapes
from . import _common as C

SHAPE_VERSION = "gh.version.v1"
SHAPE_VERIFY = "gh.attestation.verify.v1"

#: The attestation subcommand's supported range. Narrower than the `gh api` gate in
#: parsers/gh.py on purpose: `--format json` for `attestation verify` stabilised well after
#: 2.40. Validated against REAL captures from TWO in-range versions (v2.90.0 and v2.97.0,
#: both in the corpus), because v4.2.0 validated one point and claimed the range — and a
#: real second-point run is what a range claim owes.
VERSION_GATE = C.VersionGate("gh", minimum=(2, 60, 0), below=(3, 0, 0),
                             validated="v2.90.0, v2.97.0")

_RUN_INVOCATION = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/actions/runs/"
    r"(?P<run>\d+)/attempts/(?P<attempt>\d+)$")

#: An RFC 3339 INSTANT: `Z` or a numeric offset, fractional seconds optional. The history
#: of this pattern is a lesson in strictness aimed at the wrong axis. v4.2.0 pinned
#: whole-second `Z` only; v4.2.1 admitted fractional seconds; and the REAL field failure
#: turned out to be neither — gh (v2.90.0 AND v2.97.0 alike) formats the verified tlog
#: time in the machine's LOCAL zone, so a verifier in UTC+3 produced
#: `2026-08-05T00:31:32+03:00` and a UTC-only parser refused a completely valid
#: verification because of a wall-clock setting. What is enforced now is what actually
#: matters: the string denotes an EXACT INSTANT (date, time, and an explicit zone). The
#: spelling of that instant — Z or offset, fractions or not — is normalised to epoch and
#: never judged. A missing zone still refuses: a zoneless time is not an instant.
#: (`ghexec` additionally pins TZ=UTC on the subprocess, so in practice the kit's own
#: invocations produce `Z` on every machine; this tolerance is defence in depth.)
_ISO_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$")


def _gate_version(gh_version, shape_id):
    supported, code, detail = VERSION_GATE.check(gh_version)
    if not supported:
        return C.fail(shape_id, code, detail)
    return None


def parse_version(raw):
    """`gh --version` first line -> {"version": "2.97.0"}. Text, not JSON."""
    res, text = C.decode_text(raw, SHAPE_VERSION)
    if res is not None:
        return res
    match = re.match(r"^gh version (\d+\.\d+\.\d+)", text.strip())
    if not match:
        return C.unknown(SHAPE_VERSION,
                         f"`gh --version` output was not recognised: {text[:120]!r}")
    return C.ok(SHAPE_VERSION, {"version": match.group(1)})


def parse_verify_output(raw, gh_version=None, registry=None):
    """The `--format json` array -> one attestation record, or a refusal.

    STRICT ON PURPOSE, in both directions. The shape gate refuses output this kit has never
    seen for real. And when the array carries MORE than one verified attestation, every
    element must agree on the certificate identity fields — two attestations that verify but
    name different builders are a contradiction, and a contradiction is a refusal, never a
    pick-the-convenient-one.
    """
    reg = registry or shapes.registry()
    gated = _gate_version(gh_version, SHAPE_VERIFY)
    if gated is not None:
        return gated
    res, doc = C.load_json(raw, SHAPE_VERIFY)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_VERIFY, reg)
    if not good:
        return C.fail(SHAPE_VERIFY, code, detail)

    records = []
    for i, element in enumerate(doc):
        vr = element["verificationResult"]
        cert = vr["signature"]["certificate"]
        statement = vr["statement"]

        if cert["subjectAlternativeName"] != cert["buildSignerURI"]:
            return C.fail(
                SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                f"[{i}] certificate SAN {cert['subjectAlternativeName']!r} disagrees with "
                f"its own Build Signer URI {cert['buildSignerURI']!r}; the signature and "
                f"the identity are not from the same event")
        run = _RUN_INVOCATION.match(cert.get("runInvocationURI") or "")
        if not run:
            return C.unknown(SHAPE_VERIFY,
                             f"[{i}] runInvocationURI "
                             f"{cert.get('runInvocationURI')!r} is not a recognised "
                             f"GitHub Actions run URI")
        stamps = []
        for ts in vr["verifiedTimestamps"]:
            if not _ISO_UTC.match(ts["timestamp"]):
                return C.unknown(SHAPE_VERIFY,
                                 f"[{i}] verified timestamp {ts['timestamp']!r} is not "
                                 f"an RFC 3339 instant with an explicit zone")
            # fromisoformat, not strptime: it accepts every spelling the pattern above
            # admits (fractions, Z, numeric offsets) and normalises to one instant.
            # Truncating to whole seconds keeps the epoch conservative (never later than
            # the instant recorded). The two explicit refusals are belt-and-braces behind
            # the regex: a zoneless parse must never slip through to a naive timestamp()
            # (which would silently apply the LOCAL zone — the exact bug class this fix
            # closes), and an offset the regex shape admits but time arithmetic rejects
            # (e.g. minutes > 59) must refuse cleanly rather than crash the verifier.
            try:
                instant = datetime.datetime.fromisoformat(
                    ts["timestamp"].replace("Z", "+00:00"))
            except ValueError as exc:
                return C.unknown(SHAPE_VERIFY,
                                 f"[{i}] verified timestamp {ts['timestamp']!r} does not "
                                 f"denote a legal instant: {exc}")
            if instant.tzinfo is None:
                return C.unknown(SHAPE_VERIFY,
                                 f"[{i}] verified timestamp {ts['timestamp']!r} carries "
                                 f"no zone; a zoneless time is not an instant")
            epoch = int(instant.timestamp())
            stamps.append({"type": ts["type"], "uri": ts.get("uri", ""),
                           "timestamp": ts["timestamp"], "epoch": epoch})
        subjects = []
        for subject in statement["subject"]:
            digests = subject["digest"]
            subjects.append({"name": subject.get("name", ""),
                             "digest": {alg: value.lower()
                                        for alg, value in digests.items()}})
        records.append({
            "sanUri": cert["subjectAlternativeName"],
            "issuer": cert["issuer"],
            "repository": cert["githubWorkflowRepository"],
            "repositoryUri": cert["sourceRepositoryURI"],
            "repositoryId": str(cert["sourceRepositoryIdentifier"]),
            "ownerId": str(cert["sourceRepositoryOwnerIdentifier"]),
            "commit": cert["githubWorkflowSHA"].lower(),
            "sourceCommit": cert["sourceRepositoryDigest"].lower(),
            "workflowRef": cert["githubWorkflowRef"],
            "runnerEnvironment": cert["runnerEnvironment"],
            "runInvocationUri": cert["runInvocationURI"],
            "runId": run.group("run"),
            "runAttempt": run.group("attempt"),
            "predicateType": statement["predicateType"],
            "subjects": subjects,
            "verifiedTimestamps": stamps,
        })

    first = records[0]
    for i, record in enumerate(records[1:], start=1):
        for field in ("sanUri", "issuer", "repository", "repositoryId", "commit",
                      "runId", "runAttempt"):
            if record[field] != first[field]:
                return C.fail(
                    SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                    f"the output carries {len(records)} verified attestations that "
                    f"DISAGREE on {field}: [0]={first[field]!r} vs [{i}]={record[field]!r}. "
                    f"Two verifying attestations naming different events are a "
                    f"contradiction, not a choice.")
    if first["commit"] != first["sourceCommit"]:
        return C.fail(SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                      f"certificate workflow SHA {first['commit']} disagrees with its own "
                      f"source repository digest {first['sourceCommit']}")
    return C.ok(SHAPE_VERIFY, dict(first, attestationCount=len(records)))


def check_against_subject(record, *, expected_repository, expected_commit,
                          expected_artifact_digest, artifact_digest_alg,
                          expected_run_id=None):
    """Cross-check the verified attestation against the DECISION's subject. All or nothing.

    `expected_artifact_digest` is REQUIRED: the attestation binds an artifact, and a decision
    that names no artifact digest gives this path nothing to bind to. That is a refusal, not
    a soft pass on repository+commit alone — a matching repository is a weaker claim wearing
    a stronger one's clothes.
    """
    agreements, disagreements = [], []

    def compare(label, attested, expected):
        (agreements if str(attested).lower() == str(expected).lower()
         else disagreements).append(
            {"field": label, "attested": attested, "expected": expected})

    if not expected_artifact_digest:
        return C.fail(SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                      "the decision carries no subject.artifactDigest, so a verified "
                      "artifact attestation cannot be bound to it; nothing ties the "
                      "attested artifact to this decision")
    wanted = str(expected_artifact_digest).lower()
    attested_digest = None
    for subject in record["subjects"]:
        candidate = subject["digest"].get(artifact_digest_alg)
        if candidate == wanted:
            attested_digest = candidate
            break
    if attested_digest is None:
        seen = [subject["digest"] for subject in record["subjects"]]
        return C.fail(SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                      f"no attested subject carries {artifact_digest_alg} digest "
                      f"{wanted[:16]}…; the attestation is about a different artifact "
                      f"(subject digests: {seen})")

    compare("repository", record["repository"], expected_repository)
    compare("commit", record["commit"], expected_commit)
    if expected_run_id:
        compare("runId", record["runId"], expected_run_id)
    if disagreements:
        fields = ", ".join(d["field"] for d in disagreements)
        return C.fail(SHAPE_VERIFY, R.AUT_BINDING_MISMATCH,
                      f"the verified attestation disagrees with the decision on: {fields} "
                      f"({disagreements}). The certificate is signed DER that gh verified; "
                      f"when it names a different event than this decision, the evidence "
                      f"is about that other event.",
                      data={"agreements": agreements, "disagreements": disagreements})
    return C.ok(SHAPE_VERIFY, {"agreements": agreements,
                               "artifactDigest": attested_digest,
                               "artifactDigestAlg": artifact_digest_alg})


def freshness_from_record(record, max_age_seconds, now):
    """The tlog timestamp gh verified -> a freshness fact, or a refusal.

    The OLDEST verified timestamp is judged — conservative on purpose: if the log and a
    timestamp authority disagree about when this signature happened, the claim this kit
    relies on is the weaker (earlier) one.
    """
    stamps = record.get("verifiedTimestamps") or []
    if not stamps:
        return C.fail(SHAPE_VERIFY, R.AUT_FRESHNESS_EXPIRED,
                      "gh reported no verified timestamps, so when this attestation was "
                      "made cannot be established")
    oldest = min(stamps, key=lambda item: item["epoch"])
    age = now - oldest["epoch"]
    if age < 0:
        return C.fail(SHAPE_VERIFY, R.AUT_FRESHNESS_EXPIRED,
                      f"attestation is dated {-age}s in the FUTURE "
                      f"({oldest['timestamp']}); refusing forward-dated evidence")
    if age > max_age_seconds:
        return C.fail(SHAPE_VERIFY, R.AUT_FRESHNESS_EXPIRED,
                      f"attestation is {age}s old, over the {max_age_seconds}s limit "
                      f"({oldest['timestamp']}); it is not evidence about this run")
    return C.ok(SHAPE_VERIFY, {
        "source": "github-attestation-tlog",
        "integratedTime": oldest["epoch"],
        "timestamp": oldest["timestamp"],
        "tlogUri": oldest.get("uri", ""),
        "ageSeconds": age,
        "maxAgeSeconds": max_age_seconds,
        "timestampCount": len(stamps),
    })


__all__ = ["SHAPE_VERIFY", "SHAPE_VERSION", "VERSION_GATE", "check_against_subject",
           "freshness_from_record", "parse_verify_output", "parse_version"]
