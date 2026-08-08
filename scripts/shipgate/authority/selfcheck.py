"""Executable proof of every claim this kit makes. `python3 -m shipgate.authority.selfcheck`

It is inside `authority/` on purpose: the kit's own evidence must be deleted along with the
kit. Exits 0 only when every claim below holds.

  1  the package imports and reports availability with no external tool installed
  2  the shipped constants are byte-identical to the captures they were transcribed from
  3  every parser accepts every real capture, from BOTH the raw and normalized corpora
  4  every parser REJECTS every mutation, with the exact reason code the mutation implies
  5  a FAILED decision cannot be attested — by either adapter, or by AttestedDecision
  6  the gh negative fixture is refused as a trust boundary
  7  BLOCKED shapes are refused even when the input looks perfect
  8  the kit imports nothing it is not allowed to, and spawns no process
  9  the rule table cannot be talked into an upgrade
 13  the 2026-08-06 v0.3 round: RFC 6962 recomputation, the bundle/REST cross-check, the shard
     offset, and a freshness verifier finally pointed at an entry BOUND to a bundle
 14  every shape names its producing tool version AND the epistemic state of that claim; none
     says UNSTATED
 15  the v0.3 KEYLESS bundle is still BLOCKED, with digest-pinned evidence of why
 16  the four reasons no shipped capture can produce a real CI_ATTESTED, walked in code
"""
import ast
import json
import os
import sys

from ..models import reasons as R
from ..models.decision import (
    Attestation,
    AttestedDecision,
    CheckResult,
    Decision,
    ProvenanceStatus,
    SemanticStatus,
    SubjectIdentity,
)
from . import fixtures, shapes
from .ci.adapter import CiAuthorityAdapter
from .contracts import AuthorityConfig, VerifierResult, evaluate
from .independent.adapter import IndependentAuthorityAdapter
from .parsers import cosign, gh, oidc, rekor

HERE = os.path.dirname(os.path.abspath(__file__))

#: What `authority/` is allowed to import from the rest of shipgate. Everything else is a
#: layering violation that would make the kit undeletable.
ALLOWED_SHIPGATE_ROOTS = {"models", "util", "execadapter"}
FORBIDDEN_MODULES = {"subprocess", "shipgate.semantic", "shipgate.collectors",
                     "shipgate.decision", "shipgate.reporting"}

#: The ONE file allowed to spawn a process, and the ONE module it may spawn it with.
#:
#: v4.1 runs `cosign verify-blob` instead of reading a file that claims cosign ran, because
#: an external audit showed the replayed verdict was the operator asserting the answer to the
#: only question that establishes cryptographic identity. The exemption is narrow on purpose:
#: one binary resolved from the VERIFIER's PATH, argv built in code, shell=False, scrubbed
#: environment, and nothing the target controls reaching any of it. The artifact under test is
#: passed as DATA.
SUBPROCESS_EXEMPT = {"toolexec.py"}


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, label, condition, detail=""):
        if condition:
            self.passed += 1
        else:
            self.failed.append(f"{label}: {detail}")
        return bool(condition)

    def section(self, title):
        print(f"\n=== {title}")

    def line(self, text):
        print("    " + text)


# ---------------------------------------------------------------------------------------
# a decision fixture
# ---------------------------------------------------------------------------------------


#: v4.1: cosign is RUN, never replayed. This harness is OFFLINE by design and does not invoke
#: cosign, so no capture can establish `identity` or `binding` here — which is the correct
#: end state, not a gap in the harness. A recording of a verdict is not a verdict, and the
#: checks below assert that the corpus PARSES and then REFUSES, rather than asserting the
#: establishment they used to.
NOT_RUN = "AUT_NOT_CONFIGURED"


def make_decision(status=SemanticStatus.PASSED):
    """A minimal but STRUCTURALLY REAL decision. Nothing here is authority-aware."""
    passed = status is SemanticStatus.PASSED
    return Decision(
        decision_id="dec-selfcheck-0001",
        created_at="2026-08-05T12:00:00Z",
        subject=SubjectIdentity(
            repository="samerzakaria/ClearReq",
            commit="0" * 40,
            tree_digest="1" * 64,
        ),
        profile_id="standard",
        profile_digest="2" * 64,
        semantic_status=status,
        reason_codes=(R.SEM_ALL_REQUIRED_CHECKS_PASSED,) if passed
        else (R.SEM_REQUIRED_CHECK_FAILED,),
        checks=(CheckResult(check_id="wiring.routes", title="every route is served",
                            passed=passed, required=True, showstopper=True,
                            evidence_kind="RUNTIME"),),
        thresholds=(), cujs=(), heldout=(), findings=(),
        required_evidence=("RUNTIME",),
        received_evidence=({"kind": "RUNTIME", "digest": "3" * 64},),
        input_digests=({"path": "src", "digest": "4" * 64},),
        containment={"established": True, "kind": "container"},
    )


# ---------------------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------------------


def check_availability(rep):
    rep.section("1. availability with no external tool installed")
    from . import availability
    avail = availability()
    rep.line(json.dumps(avail))
    rep.check("availability.present", avail["present"] is True, str(avail))
    rep.check("availability.configured is False by default", avail["configured"] is False,
              "installing the skill must not certify any environment")
    rep.check("availability.reason", avail["reason"] == R.AUT_NOT_CONFIGURED, avail["reason"])

    reg = shapes.registry()
    rep.check("shape registry loaded", not reg.load_error, reg.load_error)
    rep.line(f"VALIDATED: {len(reg.validated_ids())}  BLOCKED: {list(reg.blocked_ids())}")


def check_constants(rep):
    rep.section("2. shipped constants match the captures byte-for-byte")
    ok_text = fixtures.load_text("cosign_verify_ok.txt").strip()
    rep.check("VERIFY_OK_TEXT", cosign.VERIFY_OK_TEXT == ok_text,
              f"{cosign.VERIFY_OK_TEXT!r} != {ok_text!r}")
    fail_lines = [ln.strip() for ln in fixtures.load_text("cosign_verify_fail.txt").splitlines()
                  if ln.strip()]
    rep.check("VERIFY_FAIL lines",
              fail_lines == [cosign.VERIFY_FAIL_LINE1, cosign.VERIFY_FAIL_LINE2],
              f"{fail_lines} != {[cosign.VERIFY_FAIL_LINE1, cosign.VERIFY_FAIL_LINE2]}")

    # The four PowerShell captures really are UTF-16 in raw and UTF-8 in normalized.
    for name in fixtures.UTF16_RAW_FILES:
        raw = fixtures.load_raw(name)
        rep.check(f"raw/{name} is UTF-16LE+BOM", raw.startswith(b"\xff\xfe"), repr(raw[:4]))
    for name in fixtures.UTF8_BOM_RAW_FILES:
        raw = fixtures.load_raw(name)
        rep.check(f"raw/{name} is UTF-8+BOM", raw.startswith(b"\xef\xbb\xbf"), repr(raw[:4]))
    rep.line(f"{len(fixtures.UTF16_RAW_FILES)} raw captures carry a UTF-16LE BOM, "
             f"{len(fixtures.UTF8_BOM_RAW_FILES)} carry a UTF-8 BOM — three encodings, all "
             "parsed from both corpora")

    # The 2026-08-06 round arrived plain UTF-8, so raw/ and normalized/ are byte-identical.
    # Both paths are populated anyway: the dual-path checks must run over every capture, not
    # only the ones where the two copies happen to differ.
    v03_files = ("bundle_v03.json", "cosign_version_3_1_3.json", "verify_v03_ok.txt",
                 "verify_v03_fail.txt", "rekor_rest_entry_fresh.json",
                 "rekor_loginfo_fresh.json", "keyless_attempt.txt", "cosign.pub")
    for name in v03_files:
        raw, norm = fixtures.load_raw(name), fixtures.load_normalized(name)
        rep.check(f"raw/{name} == normalized/{name} (plain UTF-8, no BOM)",
                  raw == norm and not raw.startswith(b"\xef\xbb\xbf")
                  and not raw.startswith(b"\xff\xfe"), repr(raw[:4]))

    # The two v3.1.3 verify-blob captures are BYTE-IDENTICAL to the v3.1.2 ones. That is the
    # finding, so it is asserted rather than mentioned: the success and rejection texts did NOT
    # drift across the version bump, and these entries buy version coverage, not shape coverage.
    for new, old in (("verify_v03_ok.txt", "cosign_verify_ok.txt"),
                     ("verify_v03_fail.txt", "cosign_verify_fail.txt")):
        rep.check(f"{new} is byte-identical to {old} (text did not drift v3.1.2 -> v3.1.3)",
                  fixtures.load_normalized(new) == fixtures.load_normalized(old),
                  "the captures differ; the shipped constants describe only one of them")


def parse_capture(shape_id, data):
    """Route a capture to its parser. Returns a ParseResult, or None for shapes with no
    single-input parser."""
    if shape_id == "cosign.version.v1":
        return cosign.parse_version(data)
    if shape_id == "cosign.bundle.keyed.v0_3":
        return cosign.parse_bundle(data, cosign_version="v3.1.2")
    if shape_id == "cosign.bundle.v0_3.keyed":
        # The SAME serialisation, from cosign v3.1.3. Same parser, different producing version.
        return cosign.parse_bundle(data, cosign_version="v3.1.3")
    if shape_id == "cosign.bundle.keyless.v0_3":
        return cosign.parse_bundle(data, cosign_version="v3.1.2")
    if shape_id == "cosign.verifyblob.v03.ok.v1":
        return cosign.parse_verify_blob(0, data, b"")
    if shape_id == "cosign.verifyblob.v03.fail.v1":
        return cosign.parse_verify_blob(1, b"", data)
    if shape_id == "rekor.rest.entry.fresh.v1":
        return rekor.parse_rest_entry(data)
    if shape_id == "rekor.rest.loginfo.v1":
        return rekor.parse_rest_loginfo(data)
    if shape_id == "cosign.bundle.keyless.legacy.v1":
        # No cosign version is asserted for this capture, so none is passed: the shape is
        # what was validated. See SHAPES.json toolVersion: UNSTATED.
        return cosign.parse_bundle(data)
    if shape_id == "gh.environment.protected.v1":
        return gh.parse_environment(data, gh_version="2.65.0")
    if shape_id == "cosign.verifyblob.ok.v1":
        return cosign.parse_verify_blob(0, data, b"")
    if shape_id == "cosign.verifyblob.fail.v1":
        return cosign.parse_verify_blob(1, b"", data)
    if shape_id == "rekor.rest.entry.v1":
        return rekor.parse_rest_entry(data)
    if shape_id == "rekor.cli.get.v1":
        return rekor.parse_cli_get(data, rekor_version="1.5.3")
    if shape_id == "rekor.cli.loginfo.v1":
        return rekor.parse_loginfo(data, rekor_version="1.5.3")
    if shape_id == "gh.repo.v1":
        return gh.parse_repo(data, gh_version="2.65.0")
    if shape_id == "gh.environment.v1":
        return gh.parse_environment(data, gh_version="2.65.0")
    if shape_id == "gh.environment.list.v1":
        return gh.parse_environment_list(data, gh_version="2.65.0")
    if shape_id == "gh.environment.secrets.v1":
        return gh.parse_environment_secrets(data, gh_version="2.65.0")
    if shape_id == "oidc.github.claims.v1":
        return oidc.parse_claims(data)
    return None


def check_positives(rep):
    rep.section("3. every parser accepts every real capture (raw AND normalized)")
    for variant in ("normalized", "raw"):
        for shape_id, name, data in fixtures.positives(variant):
            res = parse_capture(shape_id, data)
            if shape_id in ("cosign.verifyblob.fail.v1", "cosign.verifyblob.v03.fail.v1"):
                # The tamper capture is a REFUSAL that must be recognised as one.
                good = (res is not None and not res.ok
                        and res.reason_code == R.AUT_SIGNATURE_INVALID)
                rep.check(f"{variant}/{name} -> AUT_SIGNATURE_INVALID", good,
                          res.detail if res else "no parser")
                continue
            good = res is not None and res.ok
            rep.check(f"{variant}/{name} parses", good,
                      f"{res.reason_code}: {res.detail}" if res else "no parser")
    rep.line("both corpora parse identically — BOM handling is exercised, not assumed")

    # The interesting positives, spelled out.
    entry = rekor.parse_rest_entry(fixtures.load_normalized("rekor_rest_entry.json")).data
    rep.check("rekor inclusion proof verifies", entry["inclusionProofVerified"] is True)
    rep.line(f"rekor: logIndex={entry['logIndex']} treeSize={entry['treeSize']} "
             f"root={entry['rootHashHex'][:16]}… integratedTime={entry['integratedTime']}")
    secrets = gh.parse_environment_secrets(fixtures.load_normalized("env_secrets.json")).data
    rep.check("empty secrets list parses to zero, not an error",
              secrets["totalCount"] == 0 and secrets["empty"] is True, str(secrets))
    bundle = cosign.parse_bundle(fixtures.load_normalized("cosign_signblob_bundle.json"),
                                 cosign_version="v3.1.2").data
    rep.check("bundle inclusion proof verifies", bundle["inclusionProofVerified"] is True)
    rep.line(f"bundle: digest={bundle['messageDigestHex'][:16]}… "
             f"logIndex={bundle['logIndex']} checkpoint tree={bundle['checkpoint']['treeId']}")
    cli = rekor.parse_cli_get(fixtures.load_normalized("rekor_get_logindex.json"),
                              rekor_version="1.5.3").data
    rep.check("rekor-cli proof absence detected", cli["inclusionProofPresent"] is False)
    need = rekor.require_inclusion_proof(cli)
    rep.check("rekor-cli without proof is refused", not need.ok
              and need.reason_code == R.AUT_OUTPUT_SHAPE_UNKNOWN, need.detail)


def check_rejections(rep):
    rep.section("4. every mutation is rejected with the right reason code")
    for case in fixtures.rejections():
        res = parse_capture(case["shape"], case["data"])
        if res is None:
            rep.check(case["label"], False, "no parser routed")
            continue
        good = (not res.ok) and res.reason_code == case["expect"]
        rep.check(case["label"], good,
                  f"expected {case['expect']}, got "
                  f"{res.reason_code if not res.ok else 'ACCEPTED'} ({res.detail[:120]})")

    # CROSS-SOURCE mutations. Every document below parses CLEANLY on its own — that is the
    # whole point. What is under test is that two internally-valid documents describing the
    # same log entry differently produce a REFUSAL rather than a merge.
    for case in fixtures.cross_source_rejections():
        res = _cross_source_result(case)
        if res is None:
            rep.check(case["label"], False, "the case could not be set up")
            continue
        good = (not res.ok) and res.reason_code == case["expect"]
        rep.check(case["label"], good,
                  f"expected {case['expect']}, got "
                  f"{res.reason_code if not res.ok else 'ACCEPTED'} ({res.detail[:130]})")
    rep.line("cross-source: a disagreement between the bundle's own tlog record and the log's "
             "REST entry is a refusal, never a merge and never 'prefer the newer one'")


def _cross_source_result(case):
    """Run one multi-document case. None when a document that should parse did not.

    Every input here is expected to parse on its own; if one does not, the case is testing the
    wrong thing and must be reported as broken rather than silently counted as a pass.
    """
    kind = case["kind"]
    if kind == "tlog_agreement":
        bundle = cosign.parse_bundle(case["bundle"], cosign_version="v3.1.3")
        entry = rekor.parse_rest_entry(case["entry"])
        if not (bundle.ok and entry.ok):
            return None
        return cosign.check_tlog_agreement(bundle.data, entry.data)
    if kind == "shard_offset":
        entry = rekor.parse_rest_entry(case["entry"])
        info = rekor.parse_rest_loginfo(case["loginfo"])
        if not (entry.ok and info.ok):
            return None
        return rekor.check_shard_offset(entry.data, info.data)
    if kind == "freshness":
        entry = rekor.parse_rest_entry(case["entry"])
        if not entry.ok:
            return None
        return rekor.freshness(entry.data, case["max_age"], now=case["now"])
    return None


def check_failed_decision(rep):
    rep.section("5. a FAILED decision cannot be attested")
    failed = make_decision(SemanticStatus.FAILED)
    config = fixtures.evidence_config(freshness_max_age_seconds=604800)

    for name, adapter in (("ci", CiAuthorityAdapter(config)),
                          ("independent", IndependentAuthorityAdapter(
                              dict(config, mode="independent")))):
        att = adapter.attest(failed)
        rep.check(f"{name} adapter -> UNAVAILABLE",
                  att.provenance_status is ProvenanceStatus.UNAVAILABLE,
                  att.provenance_status.value)
        rep.check(f"{name} adapter -> AUT_SEMANTIC_NOT_PASSED",
                  R.AUT_SEMANTIC_NOT_PASSED in att.reason_codes, str(att.reason_codes))
        rep.check(f"{name} adapter attaches no facts",
                  att.identity is None and att.binding is None and att.freshness is None
                  and not att.principals, "a refusal must carry no positive findings")

    forged = Attestation(
        provenance_status=ProvenanceStatus.CI_ATTESTED,
        decision_digest=failed.digest(), verifier="forged", verifier_version="0",
        reason_codes=(R.AUT_CI_ATTESTED,))
    try:
        AttestedDecision(decision=failed, attestation=forged)
        rep.check("AttestedDecision(FAILED, CI_ATTESTED) raises", False, "it did NOT raise")
    except ValueError as exc:
        rep.check("AttestedDecision(FAILED, CI_ATTESTED) raises", True)
        rep.line(f"ValueError: {exc}")

    mismatched = Attestation(
        provenance_status=ProvenanceStatus.UNAVAILABLE, decision_digest="0" * 64,
        verifier="forged", verifier_version="0", reason_codes=(R.AUT_NOT_CONFIGURED,))
    try:
        AttestedDecision(decision=make_decision(), attestation=mismatched)
        rep.check("AttestedDecision rejects a foreign digest", False, "it did NOT raise")
    except ValueError:
        rep.check("AttestedDecision rejects a foreign digest", True)

    # And an adapter may not emit a semantic reason code even if it tries.
    try:
        Attestation(provenance_status=ProvenanceStatus.UNAVAILABLE,
                    decision_digest=failed.digest(), verifier="x", verifier_version="0",
                    reason_codes=(R.SEM_REQUIRED_CHECK_FAILED,))
        rep.check("Attestation rejects a SEM_ reason code", False, "it did NOT raise")
    except ValueError:
        rep.check("Attestation rejects a SEM_ reason code", True)

    # An incomplete PASSED decision is refused too.
    contradictory = make_decision()
    contradictory = Decision(**{**contradictory.__dict__,
                                "reason_codes": (R.EVD_REQUIRED_MISSING,)})
    att = CiAuthorityAdapter(config).attest(contradictory)
    rep.check("a self-contradictory PASSED decision is refused",
              att.provenance_status is ProvenanceStatus.UNAVAILABLE
              and R.AUT_SEMANTIC_NOT_PASSED in att.reason_codes, str(att.reason_codes))


def check_negative_environment(rep):
    rep.section("6. the gh negative fixture is refused as a trust boundary")
    raw = fixtures.load_normalized("env_one.json")
    qualifies, code, detail = gh.is_qualifying_environment(raw)
    rep.check("is_qualifying_environment(env_one.json) is False", qualifies is False,
              str(qualifies))
    rep.check("reason is AUT_PRINCIPAL_NOT_DISTINCT", code == R.AUT_PRINCIPAL_NOT_DISTINCT,
              str(code))
    rep.line(detail)

    raw16 = fixtures.load_raw("env_one.json")
    q2, c2, _ = gh.is_qualifying_environment(raw16)
    rep.check("same answer from the UTF-16 raw capture", q2 is False
              and c2 == R.AUT_PRINCIPAL_NOT_DISTINCT, f"{q2} {c2}")

    listed = gh.parse_environment_list(fixtures.load_normalized("env_list.json")).data
    for env in listed["environments"]:
        q3, c3, _ = gh.is_qualifying_environment(env)
        rep.check(f"listed environment {env['name']!r} refused", q3 is False
                  and c3 == R.AUT_PRINCIPAL_NOT_DISTINCT, f"{q3} {c3}")


def check_blocked_shapes(rep):
    rep.section("7. the remaining BLOCKED shape, and the newly-live branches")

    # The one shape still blocked. It is refused even though the input is a perfectly
    # plausible v0.3 keyless bundle — because THAT serialisation has never been captured.
    keyless_v03 = fixtures.synthetic("SYNTHETIC-ADVERSARIAL__cosign_bundle_keyless.json")
    res = cosign.parse_bundle(keyless_v03, cosign_version="v3.1.2")
    rep.check("a sigstore-v0.3 KEYLESS bundle is still refused", not res.ok
              and res.reason_code == R.AUT_OUTPUT_SHAPE_UNKNOWN,
              "it was ACCEPTED" if res.ok else str(res.reason_code))
    rep.line(f"v0.3 keyless -> {res.reason_code}: {res.detail[:150]}")

    reg = shapes.registry()
    rep.check("cosign.bundle.keyless.v0_3 is BLOCKED",
              reg.status("cosign.bundle.keyless.v0_3") == shapes.BLOCKED,
              reg.status("cosign.bundle.keyless.v0_3"))
    for shape_id in ("oidc.github.claims.v1", "cosign.bundle.keyless.legacy.v1",
                     "gh.environment.protected.v1"):
        rep.check(f"{shape_id} is now VALIDATED",
                  reg.status(shape_id) == shapes.VALIDATED, reg.status(shape_id))
        entry = reg.get(shape_id)
        rep.check(f"{shape_id} does NOT claim bindingValidated",
                  entry.binding_validated is False,
                  "a sanitized capture must never claim to prove a binding")

    # The synthetic fixtures now exercise the POSITIVE branches of the two predicates whose
    # shapes were unblocked. They are still labelled synthetic and still cannot validate a
    # shape — the registry only validates from captures/normalized/.
    # `is_qualifying_environment` is a POLICY predicate over a record: "do these rules
    # describe a boundary?". It is deliberately not an authenticity check, and it must never
    # be mistaken for one — a hand-authored record can satisfy it, which is exactly why the
    # principal fact is no longer established from a file. Authenticity is enforced by
    # GithubEnvironmentPrincipalVerifier (live observation only) and by contracts.evaluate
    # (an unauthenticated principal is dropped). What is asserted here is that the predicate
    # AWARDS NOTHING on its own.
    protected = fixtures.synthetic("SYNTHETIC-ADVERSARIAL__gh_env_protected.json")
    q, code, detail = gh.is_qualifying_environment(protected)
    rep.line(f"synthetic protected env -> policy predicate says qualifies={q}")
    principal_only = VerifierResult(
        verifier="synthetic", verifier_version="0", established=True,
        principal=gh.principal_from_environment(gh.parse_environment(protected).data))
    status, _, _ = evaluate(
        SemanticStatus.PASSED,
        [VerifierResult(verifier="s", verifier_version="0", established=True,
                        identity={"i": 1}),
         VerifierResult(verifier="s", verifier_version="0", established=True,
                        binding={"b": 1}),
         VerifierResult(verifier="s", verifier_version="0", established=True,
                        freshness={"f": 1}),
         principal_only],
        ceiling=ProvenanceStatus.INDEPENDENTLY_ATTESTED)
    rep.check("a synthetic qualifying environment awards NO independence",
              status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED, status.value)

    claims_synth = fixtures.synthetic("SYNTHETIC-ADVERSARIAL__oidc_claims.json")
    res = oidc.parse_claims(claims_synth)
    rep.check("a well-formed claim set now PARSES", res.ok,
              f"{res.reason_code}: {res.detail}" if not res.ok else "")
    if res.ok:
        established, code, why = oidc.establishes_identity(res.data)
        rep.check("…and still establishes NO identity", established is False
                  and code == R.AUT_IDENTITY_NOT_ESTABLISHED, str(code))
        rep.line(f"claims parsed, identity refused -> {code}")
        ok, code, _ = oidc.check_claims(res.data["claims"],
                                        expected_repository="someone/else",
                                        at_time=res.data["issuedAt"])
        rep.check("…and a foreign repository claim is refused",
                  not ok and code == R.AUT_BINDING_MISMATCH, str(code))

    # Provenance integrity: nothing here can be promoted to evidence.
    entry = shapes.ShapeEntry("fake", {"status": "VALIDATED", "provenance": "SYNTHETIC",
                                       "captureFile": "whatever.json"})
    entry._resolve()
    rep.check("SYNTHETIC provenance cannot validate a shape", entry.status == shapes.BLOCKED,
              entry.status)
    entry2 = shapes.ShapeEntry("fake2", {"status": "VALIDATED", "provenance": "REAL_CAPTURE",
                                         "captureFile": "repo.json",
                                         "captureSha256": "0" * 64})
    entry2._resolve()
    rep.check("a digest mismatch demotes a shape to BLOCKED",
              entry2.status == shapes.BLOCKED, entry2.status)
    entry3 = shapes.ShapeEntry("fake3", {
        "status": "VALIDATED", "provenance": "REAL_CAPTURE",
        "captureFile": "env_protected_one.json",
        "captureSha256": _digest_of_capture("env_protected_one.json"),
        "additionalCaptures": [{"captureFile": "env_protected_list.json",
                                "captureSha256": "0" * 64}]})
    entry3._resolve()
    rep.check("an ADDITIONAL capture with a bad digest also demotes the shape",
              entry3.status == shapes.BLOCKED, entry3.status)
    try:
        fixtures.synthetic("repo.json")
        rep.check("fixtures.synthetic refuses an unlabelled file", False, "it loaded")
    except fixtures.FixtureError:
        rep.check("fixtures.synthetic refuses an unlabelled file", True)


def _digest_of_capture(name):
    import hashlib
    return hashlib.sha256(fixtures.load_normalized(name)).hexdigest()


def check_imports(rep):
    rep.section("8. the kit imports nothing it may not, and spawns no process")
    files = sorted(_python_files())
    rep.line(f"{len(files)} python files under authority/")
    for path in files:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        rel = os.path.relpath(path, HERE)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:                       # relative import
                    names = [_resolve_relative(path, node)]
                elif node.module:
                    names = [node.module]
            for name in names:
                exempt = (os.path.basename(rel) in SUBPROCESS_EXEMPT
                          and name.split(".")[0] == "subprocess")
                rep.check(f"{rel}: forbidden import {name}",
                          exempt or not any(name == f or name.startswith(f + ".")
                                            for f in FORBIDDEN_MODULES),
                          "authority/ must not import it")
                if name.startswith("shipgate."):
                    root = name.split(".")[1]
                    rep.check(f"{rel}: shipgate.{root} is an allowed dependency",
                              root in ALLOWED_SHIPGATE_ROOTS or root == "authority",
                              f"authority/ may import only {sorted(ALLOWED_SHIPGATE_ROOTS)}")

    # The exemption is justified by HOW the trust tools are run, so check the how rather
    # than trusting the note that granted it. v4.2: BOTH executors (cosignexec, ghexec)
    # spawn through toolexec — one discipline, one exemption — so the how is checked there.
    exempt_src = os.path.join(HERE, "toolexec.py")
    if os.path.exists(exempt_src):
        with open(exempt_src, "r", encoding="utf-8") as fh:
            exempt_tree = ast.parse(fh.read(), filename=exempt_src)
        spawns = [n for n in ast.walk(exempt_tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr in ("run", "Popen", "call", "check_output")]
        rep.check("toolexec spawns at least once (or the exemption is dead code)",
                  bool(spawns), "no subprocess call found")
        for call in spawns:
            kw = {k.arg: k.value for k in call.keywords}
            rep.check("toolexec never uses a shell",
                      getattr(kw.get("shell"), "value", None) is False, str(sorted(kw)))
            rep.check("toolexec bounds every invocation with a timeout",
                      "timeout" in kw, str(sorted(kw)))
            rep.check("toolexec scrubs the environment rather than inheriting it",
                      "env" in kw, str(sorted(kw)))
    rep.check("only one authority file may spawn a process",
              SUBPROCESS_EXEMPT == {"toolexec.py"}, str(sorted(SUBPROCESS_EXEMPT)))

    # Nothing outside authority/ may IMPORT authority. Checked by AST, not by grep: the
    # semantic package's docstring says "MUST NOT import shipgate.authority", and a text
    # search would flag the very rule it is stating.
    scripts_root = os.path.dirname(os.path.dirname(HERE))
    offenders = []
    for root, dirs, names in os.walk(os.path.join(scripts_root, "shipgate")):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "authority")]
        for name in names:
            if not name.endswith(".py"):
                continue
            full = os.path.join(root, name)
            with open(full, "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=full)
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    imported = [node.module]
                elif isinstance(node, ast.ImportFrom) and node.level:
                    imported = [a.name for a in node.names]
                for mod in imported:
                    if mod == "authority" or mod.startswith("shipgate.authority"):
                        offenders.append(f"{os.path.relpath(full, scripts_root)}:{mod}")
    rep.check("nothing outside authority/ imports authority", not offenders, str(offenders))
    rep.line("authority/ is physically deletable: the VERIFIED path never imports it "
             "(gate.py probes with importlib.util.find_spec)")


def _resolve_relative(path, node):
    """Turn `from ..models import x` inside authority/ into 'shipgate.models'."""
    rel = os.path.relpath(path, os.path.dirname(os.path.dirname(HERE)))
    parts = rel.replace(os.sep, ".")[:-3].split(".")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    base = parts[:len(parts) - node.level + 1] if node.level <= len(parts) else []
    return ".".join(base + ([node.module] if node.module else []))


def _python_files():
    for root, dirs, names in os.walk(HERE):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def check_rule_table(rep):
    rep.section("9. the rule table cannot be talked into an upgrade")
    passed = make_decision()
    fact = lambda **kw: VerifierResult(verifier="synthetic", verifier_version="0",
                                       established=True, **kw)
    full = [fact(identity={"a": 1}), fact(binding={"b": 2}), fact(freshness={"c": 3}),
            fact(principal={"d": 4})]

    # A fabricated principal must NOT reach independence. This check used to assert the
    # opposite — four synthetic facts producing INDEPENDENTLY_ATTESTED — which is precisely
    # the defect an external audit found, demonstrated here as though it were coverage.
    status, codes, _ = evaluate(SemanticStatus.PASSED, full)
    rep.check("a FABRICATED principal cannot reach INDEPENDENTLY_ATTESTED",
              status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED, status.value)
    rep.check("...and it is clamped to CI_ATTESTED, not silently dropped to UNAVAILABLE",
              status is ProvenanceStatus.CI_ATTESTED, status.value)

    # v4.2: independence requires the FULL policy enforcement to pass, so the stipulated
    # best case now carries everything `enforcement.enforce_award` demands: a verified
    # builder identity (certificate SAN) on authorizedBuilders, an authorised verifier that
    # is a different principal, the policy-required environment as observed, no validity
    # window (so no external clock is needed here), and rollback protection in place.
    # Stipulating LESS than this must refuse — the checks below assert exactly that.
    builder_wf = "https://github.com/acme/app/.github/workflows/build.yml@refs/heads/main"
    auditor_wf = ("https://github.com/sec-org/verify/.github/workflows/verify.yml"
                  "@refs/heads/main")
    stip_policy = {"repository": "acme/app", "version": 7,
                   "authorizedBuilders": [builder_wf],
                   "authorizedVerifiers": [auditor_wf],
                   "requiredEnvironment": "production",
                   "notBefore": None, "notAfter": None,
                   "policyDigest": "p" * 64, "rollbackChecked": True,
                   "highestSeenVersion": 7}
    stip_deployment = {
        "repositoryId": "495574555", "runId": "12345", "runAttempt": "1",
        "runHeadSha": "c" * 40, "runActorId": "1", "deploymentId": 991,
        "environment": "production", "deploymentSha": "c" * 40,
        "statusState": "success", "statusRunBound": True,
        "approvals": [{"approverId": "999999999",
                       "approverLogin": "independent-auditor", "state": "approved"}],
        "selfReviewPrevented": True, "adminBypassDisabled": True,
        "branchPolicySatisfied": True,
    }
    authentic = [fact(identity={"kind": "fulcio-keyless-certificate",
                                "sanUri": builder_wf, "subject": builder_wf,
                                "ids": {"ownerId": 1}}),
                 full[1], full[2],
                 fact(principal={
                     "d": 4, "authenticated": True,
                     "observedFrom": "https://api.github.com/repos/x/y",
                     "environment": "production",
                     "deployment": stip_deployment,
                     "binding": {"decisionDigest": passed.digest(),
                                 "commit": "c" * 40,
                                 "runId": "12345",
                                 "observationMode": "signed-replay",
                                 # v4.1: WHO observed must be proved by signature. A constant
                                 # string used to be the default here, which made the
                                 # same-party rule vacuous.
                                 "verifierIdentity": auditor_wf,
                                 "ids": {"ownerId": 2},
                                 "verifierIdentityVerified": True,
                                 "verifierAuthorized": True,
                                 "environment": "production",
                                 "policy": stip_policy}})]
    status, codes, _ = evaluate(SemanticStatus.PASSED, authentic)
    rep.check("an OBSERVED, BOUND and POLICY-SATISFYING principal reaches "
              "INDEPENDENTLY_ATTESTED", status is ProvenanceStatus.INDEPENDENTLY_ATTESTED,
              f"{status.value} {codes}")
    for broken, why in (
            (dict(stip_policy, rollbackChecked=False), "unprotected rollback state"),
            (dict(stip_policy, authorizedBuilders=[
                "https://github.com/acme/app/.github/workflows/other.yml@refs/heads/main"]),
             "an unauthorised builder"),
            (dict(stip_policy, requiredEnvironment="staging"), "a wrong environment"),
            (dict(stip_policy, notBefore=1, notAfter=2), "a window with no external clock"),
            (None, "a missing policy record")):
        weakened = [authentic[0], authentic[1], authentic[2],
                    fact(principal=dict(authentic[3].principal,
                                        binding=dict(authentic[3].principal["binding"],
                                                     policy=broken)))]
        status, _, _ = evaluate(SemanticStatus.PASSED, weakened)
        rep.check(f"{why} demotes the award below independence",
                  status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED, status.value)
    for broken_dep, why in (
            (None, "no deployment evidence at all"),
            (dict(stip_deployment, statusState="in_progress"), "an unfinished deployment"),
            (dict(stip_deployment, deploymentSha="e" * 40), "a deployment of another commit"),
            (dict(stip_deployment, runId="99999"), "a deployment from another run"),
            (dict(stip_deployment, approvals=[{"approverId": "1", "approverLogin": "me",
                                               "state": "approved"}]),
             "a self-approved deployment"),
            (dict(stip_deployment, adminBypassDisabled=False), "a bypassable environment")):
        weakened = [authentic[0], authentic[1], authentic[2],
                    fact(principal=dict(authentic[3].principal,
                                        deployment=broken_dep))]
        status, codes, _ = evaluate(SemanticStatus.PASSED, weakened)
        rep.check(f"{why} demotes the award below independence",
                  status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED
                  and R.AUT_DEPLOYMENT_NOT_BOUND in codes,
                  f"{status.value} {codes}")
    for missing in ("authenticated", "observedFrom", "binding"):
        partial = dict(authentic[3].principal)
        partial.pop(missing)
        status, _, _ = evaluate(SemanticStatus.PASSED,
                                full[:3] + [fact(principal=partial)])
        rep.check(f"a principal missing {missing!r} does not reach independence",
                  status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED, status.value)
    status, codes, _ = evaluate(SemanticStatus.PASSED, full)
    status, _, _ = evaluate(SemanticStatus.PASSED, full,
                            ceiling=ProvenanceStatus.CI_ATTESTED)
    rep.check("the CI ceiling clamps INDEPENDENTLY_ATTESTED down to CI_ATTESTED",
              status is ProvenanceStatus.CI_ATTESTED, status.value)
    status, codes, _ = evaluate(SemanticStatus.PASSED, full[:3])
    rep.check("no principal -> CI_ATTESTED only", status is ProvenanceStatus.CI_ATTESTED,
              status.value)
    status, codes, _ = evaluate(SemanticStatus.PASSED, [full[1], full[2], full[3]])
    rep.check("no identity -> UNAVAILABLE", status is ProvenanceStatus.UNAVAILABLE,
              status.value)
    rep.check("… and it says why", R.AUT_IDENTITY_NOT_ESTABLISHED in codes, str(codes))
    status, codes, _ = evaluate(SemanticStatus.FAILED, full)
    rep.check("FAILED semantics beat every fact", status is ProvenanceStatus.UNAVAILABLE
              and codes[0] == R.AUT_SEMANTIC_NOT_PASSED, f"{status.value} {codes}")

    # An unestablished verifier cannot smuggle facts in.
    try:
        VerifierResult(verifier="x", verifier_version="0", established=False,
                       identity={"a": 1})
        rep.check("unestablished verifier cannot attach facts", False, "it was allowed")
    except Exception:
        rep.check("unestablished verifier cannot attach facts", True)

    # Strict config.
    for bad, why in (({"mode": "ci", "cosign": {"bundl": "x"}}, "typo'd key"),
                     ({"mode": "supreme"}, "unknown mode"),
                     ({"mode": "ci", "freshnessMaxAgeSeconds": 99999999}, "absurd freshness"),
                     ({"mode": "ci", "extra": 1}, "unknown top-level key")):
        try:
            AuthorityConfig.from_json(bad)
            rep.check(f"config rejects {why}", False, "it was accepted")
        except Exception:
            rep.check(f"config rejects {why}", True)


def check_end_to_end(rep):
    rep.section("10. end-to-end against the real captures (the honest result)")
    decision = make_decision()
    config = fixtures.evidence_config(freshness_max_age_seconds=604800)

    ci = CiAuthorityAdapter(config).attest(decision)
    rep.line(f"CI adapter -> {ci.provenance_status.value} {list(ci.reason_codes)}")
    rep.check("CI adapter refuses (no validated identity shape)",
              ci.provenance_status is ProvenanceStatus.UNAVAILABLE, ci.provenance_status.value)

    ind = IndependentAuthorityAdapter(dict(config, mode="independent")).attest(decision)
    rep.line(f"independent adapter -> {ind.provenance_status.value} "
             f"{list(ind.reason_codes)}")
    rep.check("independent adapter refuses",
              ind.provenance_status is ProvenanceStatus.UNAVAILABLE,
              ind.provenance_status.value)
    rep.check("independent refusal names the principal problem",
              R.AUT_PRINCIPAL_NOT_DISTINCT in ind.reason_codes, str(ind.reason_codes))

    # Binding: a decision whose digest is NOT what the bundle signed must be refused, and a
    # decision whose digest IS what the bundle signed must bind.
    from .verifiers import CosignBundleVerifier
    cfg = AuthorityConfig.coerce(config)
    res = CosignBundleVerifier().verify(decision, cfg)
    rep.check("cosign binding refuses a foreign digest", not res.established,
              str(res.reason_codes))
    rep.line(f"binding refusal: {res.detail[:160]}")

    class _Bound:
        """The decision the captured bundle would have been signing."""
        subject = decision.subject
        semantic_status = SemanticStatus.PASSED
        reason_codes = decision.reason_codes
        checks = decision.checks
        break_glass = None

        @staticmethod
        def digest():
            return fixtures.bundle_message_digest_hex()

    res = CosignBundleVerifier().verify(_Bound, cfg)
    rep.check("a matching digest still does NOT establish without cosign being run",
              not res.established and NOT_RUN in res.reason_codes,
              f"{res.reason_codes} {res.detail}")
    if res.established:
        rep.line(f"binding: {json.dumps(res.binding)[:200]}")

    # Freshness. The captured Rekor entry is a real PUBLIC entry from 2021, so it can never
    # be fresh against a real clock — and it must not be. The freshness FUNCTION is proved
    # against a reference time just after the entry was integrated; the VERIFIER is proved to
    # refuse the same entry against the real clock.
    from .verifiers import RekorTransparencyVerifier
    entry = rekor.parse_rest_entry(fixtures.load_normalized("rekor_rest_entry.json")).data
    fresh = rekor.freshness(entry, 3600, now=entry["integratedTime"] + 60)
    rep.check("freshness ESTABLISHES from integratedTime at a reference clock", fresh.ok,
              f"{fresh.reason_code}: {fresh.detail}")
    if fresh.ok:
        rep.line(f"freshness: source={fresh.data['source']} age={fresh.data['ageSeconds']}s")
    future = rekor.freshness(entry, 3600, now=entry["integratedTime"] - 60)
    rep.check("a future-dated entry is refused", not future.ok
              and future.reason_code == R.AUT_FRESHNESS_EXPIRED, str(future.reason_code))

    stale = RekorTransparencyVerifier().verify(decision, cfg)
    rep.check("the 2021 capture is correctly STALE against the real clock",
              not stale.established and R.AUT_FRESHNESS_EXPIRED in stale.reason_codes,
              str(stale.reason_codes))
    rep.line(f"stale: {stale.detail[:140]}")

    # Composite: REAL binding + REAL freshness + the identity fact we cannot obtain. This is
    # the only place a fabricated fact appears anywhere in this kit, it is labelled as such,
    # and it exists to show that the rule table integrates real verifier output correctly.
    real_binding = CosignBundleVerifier().verify(_Bound, cfg)
    synthetic_identity = VerifierResult(
        verifier="SYNTHETIC-ADVERSARIAL-identity", verifier_version="0", established=True,
        identity={"SYNTHETIC": True, "note": "stands in for the BLOCKED oidc/keyless shape"})
    real_freshness = VerifierResult(
        verifier="rekor-transparency", verifier_version="real-capture", established=True,
        freshness=dict(fresh.data))
    status, codes, _ = evaluate(SemanticStatus.PASSED,
                                [synthetic_identity, real_binding, real_freshness],
                                ceiling=ProvenanceStatus.CI_ATTESTED)
    rep.check("captures alone reach NO attested status (cosign was not run)",
              status is ProvenanceStatus.UNAVAILABLE, f"{status.value} {codes}")
    status, _, _ = evaluate(SemanticStatus.PASSED,
                            [synthetic_identity, real_binding, real_freshness],
                            ceiling=ProvenanceStatus.INDEPENDENTLY_ATTESTED)
    rep.check("… and certainly not independent",
              status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED, status.value)


def check_wiring(rep):
    rep.section("11. config pins and cross-checks are wired, not decorative")
    import shutil
    import tempfile
    from .verifiers import GithubEnvironmentPrincipalVerifier, GithubOidcIdentityVerifier
    decision = make_decision()

    with tempfile.TemporaryDirectory(prefix="shipgate-selfcheck-") as tmp:
        for name in fixtures.CAPTURE_FILES:
            shutil.copy(fixtures.normalized_path(name), os.path.join(tmp, name))
        shutil.copy(os.path.join(fixtures.TESTS_DATA_DIR,
                                 "SYNTHETIC-ADVERSARIAL__oidc_claims.json"),
                    os.path.join(tmp, "oidc_claims.json"))
        base = fixtures.evidence_config(directory=tmp, mode="independent",
                                        freshness_max_age_seconds=604800)

        # expectedSubject is a CROSS-CHECK, never an override.
        cfg = AuthorityConfig.coerce(dict(
            base, expectedSubject={"repository": "someone-else/other-repo"}))
        res = GithubEnvironmentPrincipalVerifier().verify(decision, cfg)
        rep.check("expectedSubject disagreeing with the decision is a refusal",
                  not res.established and R.AUT_BINDING_MISMATCH in res.reason_codes,
                  str(res.reason_codes))
        rep.line(res.detail[:170])

        # The environment must appear in this repository's environment list.
        cfg = AuthorityConfig.coerce(dict(base, gh=dict(base["gh"],
                                                        environmentList="env_list.json")))
        res = GithubEnvironmentPrincipalVerifier().verify(decision, cfg)
        rep.check("the listed environment cross-check runs and the negative fixture still "
                  "fails on the principal", not res.established
                  and R.AUT_PRINCIPAL_NOT_DISTINCT in res.reason_codes, str(res.reason_codes))

        foreign = json.loads(fixtures.load_text("env_list.json"))
        foreign["environments"][0]["id"] = 999999
        _write_text(os.path.join(tmp, "env_list_foreign.json"), json.dumps(foreign))
        cfg = AuthorityConfig.coerce(dict(base, gh=dict(
            base["gh"], environmentList="env_list_foreign.json")))
        res = GithubEnvironmentPrincipalVerifier().verify(decision, cfg)
        # Refused either for the list mismatch or, now, because a FILE cannot supply a
        # principal at all. Both are refusals and either is correct; what must never happen
        # is `established`.
        rep.check("an environment absent from the repository's list is refused",
                  not res.established, str(res.reason_codes))

        # OIDC: the synthetic claim set reaches check_claims and gets a SPECIFIC refusal.
        cfg = AuthorityConfig.coerce(dict(base, oidc={
            "claims": "oidc_claims.json",
            "expectedAudience": "shipgate-authority"}))
        res = GithubOidcIdentityVerifier().verify(decision, cfg)
        specific = {R.AUT_IDENTITY_NOT_PERMITTED, R.AUT_BINDING_MISMATCH}
        rep.check("a foreign claim set gets a SPECIFIC refusal, not a generic one",
                  (not res.established) and bool(specific & set(res.reason_codes)),
                  str(res.reason_codes))
        rep.line(f"oidc refusal {res.reason_codes}: {res.detail[:180]}")

        cfg = AuthorityConfig.coerce(dict(base, oidc={
            "claims": "oidc_claims.json", "expectedIssuer": "https://evil.example/oidc"}))
        res = GithubOidcIdentityVerifier().verify(decision, cfg)
        rep.check("config may pin the issuer but not widen it",
                  not res.established and R.AUT_IDENTITY_NOT_PERMITTED in res.reason_codes,
                  str(res.reason_codes))

        # A missing evidence file is AUT_TOOL_MISSING, not a crash and not a pass.
        os.remove(os.path.join(tmp, "cosign_signblob_bundle.json"))
        att = IndependentAuthorityAdapter(base).attest(decision)
        rep.check("a missing evidence file -> UNAVAILABLE + AUT_TOOL_MISSING",
                  att.provenance_status is ProvenanceStatus.UNAVAILABLE
                  and R.AUT_TOOL_MISSING in att.reason_codes, str(att.reason_codes))


def _write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def check_keyless_identity_path(rep):
    rep.section("12. the KEYLESS identity path, walked end to end")
    import shutil
    import tempfile
    from .verifiers import CosignBundleVerifier
    from .parsers import cosign as cosign_parser

    keyless = cosign.parse_bundle(fixtures.load_normalized("cosign_keyless_bundle.json"))
    rep.check("the keyless bundle parses", keyless.ok,
              f"{keyless.reason_code}: {keyless.detail}" if not keyless.ok else "")
    if not keyless.ok:
        return
    bundle = keyless.data
    cert = bundle["certificate"]
    rep.line(f"cert: issuer {cert['issuerO']}/{cert['issuerCN']}, EKU {cert['eku']}, "
             f"SCT {cert['hasEmbeddedSct']}, lifetime {cert['lifetimeSeconds']}s")
    rep.line(f"identity: {bundle['identity']['sourceRepository']} @ "
             f"{bundle['identity']['sourceRepositoryRef']} "
             f"({bundle['identity']['runnerEnvironment']})")
    rep.check("the certificate presents as a Fulcio leaf",
              cert["issuerO"] == "sigstore.dev" and cert["hasEmbeddedSct"]
              and cert["lifetimeSeconds"] <= 3600, str(cert))
    rep.check("the certificate's own signature is NOT claimed to be verified",
              cert["signatureVerified"] is False and cert["chainVerified"] is False)
    rep.check("integratedTime falls inside the certificate validity window",
              cert["notBefore"] <= bundle["integratedTime"] <= cert["notAfter"],
              f"{cert['notBefore']} <= {bundle['integratedTime']} <= {cert['notAfter']}")
    rep.check("the legacy bundle carries NO inclusion proof, and says so",
              bundle["inclusionProofPresent"] is False
              and bundle["inclusionProofVerified"] is False)

    # --- THE SANITIZATION CONFLICT, live -----------------------------------------------
    claims = oidc.parse_claims(fixtures.load_normalized("oidc_claims.json")).data["claims"]
    check = cosign_parser.check_certificate_identity(
        bundle, expected_repository=claims["repository"], claims=claims)
    rep.check("cert identity vs sanitized JSON: REFUSED, not relaxed",
              (not check.ok) and check.reason_code == R.AUT_BINDING_MISMATCH,
              "the strict identity check passed a sanitized fixture — it must not")
    agreed = [a["field"] for a in check.data["agreements"]]
    disagreed = [d["field"] for d in check.data["disagreements"]]
    rep.line(f"agree ({len(agreed)}): {agreed}")
    rep.line(f"disagree ({len(disagreed)}): {disagreed}")
    rep.check("the UNSANITIZED fields still agree",
              {"repositoryOwnerId", "commitSha", "ref", "oidcIssuer"} <= set(agreed),
              str(agreed))
    rep.check("the SANITIZED name strings are what disagree",
              "repository" in disagreed, str(disagreed))
    rep.check("the certificate's repository is the unsanitized one",
              check.data["certificateRepository"] == fixtures.CERT_REPOSITORY,
              str(check.data["certificateRepository"]))

    # --- the verifier, against a decision that matches the CERTIFICATE ------------------
    class _Signed:
        """The decision the captured keyless bundle would have been signing: the digest it
        signs, and the repository its certificate names."""
        subject = SubjectIdentity(repository=fixtures.CERT_REPOSITORY, commit="c" * 40,
                                  tree_digest="d" * 64)
        semantic_status = SemanticStatus.PASSED
        reason_codes = (R.SEM_ALL_REQUIRED_CHECKS_PASSED,)
        checks = make_decision().checks
        break_glass = None

        @staticmethod
        def digest():
            return fixtures.keyless_message_digest_hex()

    with tempfile.TemporaryDirectory(prefix="shipgate-keyless-") as tmp:
        for name in fixtures.CAPTURE_FILES:
            shutil.copy(fixtures.normalized_path(name), os.path.join(tmp, name))

        # (a) claims configured -> the sanitized claim set contradicts the certificate.
        cfg = AuthorityConfig.coerce(fixtures.keyless_config(directory=tmp))
        res = CosignBundleVerifier().verify(_Signed, cfg)
        rep.check("with the sanitized claim set configured, the verifier REFUSES",
                  not res.established, str(res.reason_codes))
        rep.line(f"corroboration refusal: {res.detail[:170]}")

        # (b) no claim set -> the certificate alone, and it names this subject.
        raw = fixtures.keyless_config(directory=tmp)
        raw.pop("oidc")
        cfg = AuthorityConfig.coerce(raw)
        res = CosignBundleVerifier().verify(_Signed, cfg)
        rep.check("without the sanitized claims it STILL does not establish, unrun",
                  (not res.established) and NOT_RUN in res.reason_codes,
                  f"{res.reason_codes} {res.detail}")
        if res.established:
            rep.line(f"identity: {res.identity['sourceRepository']} "
                     f"kind={res.identity['kind']} verifiedBy={res.identity['verifiedBy']}")
            rep.line(f"binding:  keyless={res.binding['keyless']} "
                     f"digest={res.binding['decisionDigest'][:16]}…")
            rep.check("the established identity still records signatureVerified=false",
                      res.identity["signatureVerified"] is False,
                      "the kit must never claim to have verified the certificate itself")

            # (c) the rule table, on REAL identity + REAL binding + freshness at the moment
            #     of signing. The only non-real input is the clock reference.
            fresh = rekor.freshness(bundle, 3600, now=fixtures.KEYLESS_SIGNED_AT + 30)
            rep.check("freshness from the keyless bundle's own integratedTime", fresh.ok,
                      f"{fresh.reason_code}: {fresh.detail}" if not fresh.ok else "")
            freshness_fact = VerifierResult(
                verifier="rekor-transparency", verifier_version="from-capture",
                established=True, freshness=dict(fresh.data, inclusionProofVerified=False))
            status, codes, _ = evaluate(SemanticStatus.PASSED, [res, freshness_fact],
                                        ceiling=ProvenanceStatus.CI_ATTESTED)
            rep.check("real identity + real binding + freshness -> CI_ATTESTED",
                      status is ProvenanceStatus.CI_ATTESTED, f"{status.value} {codes}")
            rep.check("the award carries no contradicting reason code",
                      R.AUT_IDENTITY_NOT_ESTABLISHED not in codes, str(codes))
            rep.line(f"CI_ATTESTED reached with codes {list(codes)}")

            # (d) INDEPENDENTLY_ATTESTED needs one more thing the corpus does not contain.
            status, codes, _ = evaluate(SemanticStatus.PASSED, [res, freshness_fact],
                                        ceiling=ProvenanceStatus.INDEPENDENTLY_ATTESTED)
            rep.check("…but NOT independent without a qualifying principal",
                      status is ProvenanceStatus.CI_ATTESTED, status.value)

            qualifying = [c for c in fixtures.qualification_cases() if c["qualifies"]][0]
            record = gh.parse_environment(qualifying["data"]).data
            principal_fact = VerifierResult(
                verifier="github-environment-principal",
                verifier_version="DERIVED-FROM-CAPTURE", established=True,
                principal=gh.principal_from_environment(record))
            status, codes, _ = evaluate(
                SemanticStatus.PASSED, [res, freshness_fact, principal_fact],
                ceiling=ProvenanceStatus.INDEPENDENTLY_ATTESTED)
            rep.check("a capture-DERIVED environment does NOT reach INDEPENDENTLY_ATTESTED",
                      status is not ProvenanceStatus.INDEPENDENTLY_ATTESTED,
                      f"{status.value} {codes}")
            rep.line("the environment fact above is DERIVED from a capture (three flags "
                     "fixed) and is therefore unauthenticated. It reaches CI_ATTESTED and "
                     "stops. INDEPENDENTLY_ATTESTED requires a LIVE observation bound to the "
                     "decision, which no shipped fixture can produce and this corpus must "
                     "never appear to.")


def check_v03_round(rep):
    rep.section("13. the 2026-08-06 v0.3 round: a bound, proof-carrying, FRESH Rekor entry")
    import base64

    bundle_res = cosign.parse_bundle(fixtures.load_normalized("bundle_v03.json"),
                                     cosign_version="v3.1.3")
    rep.check("bundle_v03.json parses", bundle_res.ok,
              f"{bundle_res.reason_code}: {bundle_res.detail}" if not bundle_res.ok else "")
    if not bundle_res.ok:
        return
    bundle = bundle_res.data

    # --- PREMISE CORRECTION, asserted rather than asserted-about ------------------------
    # The v0.3 keyed ENVELOPE was NOT first captured here. cosign_signblob_bundle.json has been
    # a mediaType v0.3+json bundle with verificationMaterial.tlogEntries and an embedded
    # inclusion proof since the original round. Two entries now pin that one serialisation.
    old_res = cosign.parse_bundle(fixtures.load_normalized("cosign_signblob_bundle.json"),
                                  cosign_version="v3.1.2")
    rep.check("the ORIGINAL capture was already a v0.3 envelope, not something newer",
              old_res.ok and old_res.data["mediaType"] == cosign.SUPPORTED_MEDIA_TYPE
              and old_res.data["inclusionProofVerified"] is True,
              "cosign_signblob_bundle.json is not a v0.3 bundle with a verified proof")
    reg = shapes.registry()
    for group, label in ((cosign.KEYED_V03_SHAPES, "keyed v0.3 bundle"),
                         (cosign.VERIFY_OK_SHAPES, "verify-blob success text"),
                         (cosign.VERIFY_FAIL_SHAPES, "verify-blob rejection text"),
                         (rekor.REST_SHAPES, "Rekor REST entry")):
        schemas = {reg.get(s).schema_file for s in group if reg.get(s)}
        rep.check(f"the {label} set is ONE serialisation captured {len(group)}x "
                  "(same schemaFile)", len(schemas) == 1, str(sorted(schemas)))
        rep.check(f"every member of the {label} set is registered AND live",
                  all(reg.status(s) == shapes.VALIDATED for s in group),
                  str({s: reg.status(s) for s in group}))
        # Redundancy has to be real: knock out the canonical capture and the shape must stay
        # parseable from the other one. Otherwise the second entry is decoration.
        survivor = reg.first_validated(*group)
        rep.check(f"the {label} set survives losing its canonical member",
                  reg.first_validated(*group[1:]) is not None and survivor == group[0],
                  f"first_validated={survivor}, without it="
                  f"{reg.first_validated(*group[1:])}")
    rep.line("cosign.bundle.keyed.v0_3 (v3.1.2) and cosign.bundle.v0_3.keyed (v3.1.3) are the "
             "SAME shape captured twice; near-identical ids, so it is asserted, not assumed")

    # --- RFC 6962, recomputed HERE rather than taken from the parser --------------------
    doc = json.loads(fixtures.load_text("bundle_v03.json"))
    entry_doc = doc["verificationMaterial"]["tlogEntries"][0]
    body = base64.b64decode(entry_doc["canonicalizedBody"])
    leaf = _leaf_hash(body)
    proof = entry_doc["inclusionProof"]
    recomputed = rekor.verify_inclusion_proof(
        leaf_hash=leaf, log_index=int(proof["logIndex"]), tree_size=int(proof["treeSize"]),
        hashes=proof["hashes"], root_hash=proof["rootHash"], encoding="base64",
        shape_id=cosign.SHAPE_BUNDLE_KEYED_V03)
    rep.check("bundle_v03 inclusion proof: recomputed Merkle root MATCHES the claimed root",
              recomputed.ok, f"{recomputed.reason_code}: {recomputed.detail}"
              if not recomputed.ok else "")
    if recomputed.ok:
        rep.line(f"RFC 6962: leaf sha256(0x00||body)={leaf.hex()[:16]}… at shard index "
                 f"{proof['logIndex']} of {proof['treeSize']} over "
                 f"{recomputed.data['proofLength']} sibling hashes -> root "
                 f"{recomputed.data['rootHashHex']}")

    # --- messageDigest vs the logged body -----------------------------------------------
    body_doc = json.loads(body)
    logged = body_doc["spec"]["data"]["hash"]
    signed = base64.b64decode(doc["messageSignature"]["messageDigest"]["digest"]).hex()
    rep.check("messageSignature.messageDigest == the canonicalizedBody's data hash",
              logged.get("algorithm") == "sha256" and logged.get("value") == signed,
              f"{logged} vs {signed}")
    rep.check("messageSignature.signature == the logged signature",
              body_doc["spec"]["signature"]["content"] == doc["messageSignature"]["signature"])
    # The key hint is recomputed from the SEPARATELY captured public key, not from the copy
    # inside the log entry — otherwise the check would only prove the entry agrees with itself.
    spki = cosign._spki_from_pem(fixtures.load_normalized("cosign.pub"))
    rep.check("publicKey.hint == b64(sha256(SPKI DER of the captured cosign.pub))",
              spki is not None and base64.b64encode(
                  _sha256(spki)).decode("ascii") == bundle["publicKeyHint"],
              str(bundle["publicKeyHint"]))

    # --- the bundle and the REST entry, cross-checked ------------------------------------
    entry_res = rekor.parse_rest_entry(
        fixtures.load_normalized("rekor_rest_entry_fresh.json"))
    rep.check("rekor_rest_entry_fresh.json parses", entry_res.ok,
              f"{entry_res.reason_code}: {entry_res.detail}" if not entry_res.ok else "")
    if not entry_res.ok:
        return
    entry = entry_res.data
    agree = cosign.check_tlog_agreement(bundle, entry)
    rep.check("the bundle's tlog entry and the REST entry describe the SAME entry", agree.ok,
              f"{agree.reason_code}: {agree.detail}" if not agree.ok else "")
    rep.check("…same logIndex", bundle["logIndex"] == entry["logIndex"]
              == fixtures.FRESH_LOG_INDEX, f"{bundle['logIndex']} vs {entry['logIndex']}")
    rep.check("…same integratedTime", bundle["integratedTime"] == entry["integratedTime"]
              == fixtures.FRESH_INTEGRATED_AT,
              f"{bundle['integratedTime']} vs {entry['integratedTime']}")
    rep.check("…and byte-identical logged bodies (the Merkle LEAF, not just matching integers)",
              bundle["bodyB64"] == entry["bodyB64"] and bundle["leafHashHex"]
              == entry["leafHashHex"], "the two sources logged different bytes")
    rep.check("the two proofs are against DIFFERENT tree heads, and that is correct",
              bundle["treeSize"] < entry["treeSize"],
              f"bundle {bundle['treeSize']} vs rekor {entry['treeSize']}")
    rep.line(f"bundle proof @treeSize {bundle['treeSize']}, REST proof @treeSize "
             f"{entry['treeSize']} — {entry['treeSize'] - bundle['treeSize']} leaves were "
             "appended between signing and fetching; requiring equality would reject every "
             "honest re-fetch")

    # --- SHARDING ------------------------------------------------------------------------
    info_res = rekor.parse_rest_loginfo(fixtures.load_normalized("rekor_loginfo_fresh.json"))
    rep.check("rekor_loginfo_fresh.json parses", info_res.ok,
              f"{info_res.reason_code}: {info_res.detail}" if not info_res.ok else "")
    if info_res.ok:
        offset = rekor.check_shard_offset(entry, info_res.data)
        rep.check("the shard offset is arithmetic, not coincidence", offset.ok,
                  f"{offset.reason_code}: {offset.detail}" if not offset.ok else "")
        rep.check("…and it equals the corpus constant",
                  entry["shardOffset"] == fixtures.FRESH_SHARD_OFFSET,
                  f"{entry['shardOffset']} != {fixtures.FRESH_SHARD_OFFSET}")
        if offset.ok:
            sizes = " + ".join(str(s["treeSize"]) for s in offset.data["inactiveShards"])
            rep.line(f"global {entry['logIndex']} - shard-local {entry['proofLogIndex']} = "
                     f"{entry['shardOffset']} = {sizes} (the sealed shards)")
    # The old parser required proof.logIndex == entry.logIndex. That was never a real check —
    # it was a property of the single 2021 fixture — and it rejected this capture outright.
    old_entry = rekor.parse_rest_entry(fixtures.load_normalized("rekor_rest_entry.json"))
    rep.check("the 2021 entry still parses (its offset is 0: it predates every shard split)",
              old_entry.ok and old_entry.data["shardOffset"] == 0,
              str(old_entry.data["shardOffset"]) if old_entry.ok else old_entry.detail)

    # --- FRESHNESS, against a REFERENCE clock and never the wall clock -------------------
    # This entry was ~29 minutes old when it was registered. Asserting "fresh against
    # datetime.now()" would pass on the day it was written and fail forever after, which is a
    # worse test than none. The verifier is exercised at fixed reference instants instead —
    # exactly how the 2021 entry has always been exercised.
    accepted = rekor.freshness(entry, 3600, now=fixtures.FRESH_INTEGRATED_AT + 60)
    rep.check("freshness ACCEPTS the bound entry inside the window", accepted.ok,
              f"{accepted.reason_code}: {accepted.detail}" if not accepted.ok else "")
    if accepted.ok:
        rep.line(f"accepted: age={accepted.data['ageSeconds']}s of "
                 f"{accepted.data['maxAgeSeconds']}s, source={accepted.data['source']}, "
                 f"logIndex={accepted.data['logIndex']}")
    edge = rekor.freshness(entry, 3600, now=fixtures.FRESH_INTEGRATED_AT + 3600)
    rep.check("…still accepted exactly AT the limit", edge.ok, str(edge.detail))
    expired = rekor.freshness(entry, 3600, now=fixtures.FRESH_INTEGRATED_AT + 3601)
    rep.check("freshness REFUSES it one second outside the window",
              not expired.ok and expired.reason_code == R.AUT_FRESHNESS_EXPIRED,
              str(expired.reason_code))
    future = rekor.freshness(entry, 3600, now=fixtures.FRESH_INTEGRATED_AT - 1)
    rep.check("…and refuses it forward-dated", not future.ok
              and future.reason_code == R.AUT_FRESHNESS_EXPIRED, str(future.reason_code))
    stale_2021 = rekor.freshness(old_entry.data, 3600, now=fixtures.FRESH_INTEGRATED_AT)
    rep.check("the 2021 entry is KEPT as the permanent NEGATIVE fixture",
              not stale_2021.ok and stale_2021.reason_code == R.AUT_FRESHNESS_EXPIRED,
              str(stale_2021.reason_code))
    rep.line("WHAT ACTUALLY CHANGED: the freshness verifier can now be exercised against an "
             "entry that is BOUND to a bundle in the corpus. It could only ever be pointed at "
             "the unrelated 2021 record before. The entry is still perishable — it is stale "
             "against a real clock about an hour after capture — so the corpus proves the "
             "verifier works on a bound entry, not that a shipped capture is permanently fresh.")

    # --- the whole chain, end to end, against the real adapters --------------------------
    decision = make_decision()
    config = fixtures.fresh_evidence_config(freshness_max_age_seconds=604800)
    from .verifiers import RekorTransparencyVerifier
    cfg = AuthorityConfig.coerce(config)
    res = RekorTransparencyVerifier().verify(decision, cfg)
    rep.check("the Rekor verifier ESTABLISHES freshness on the bound entry", res.established,
              f"{res.reason_codes} {res.detail}")
    if res.established:
        rep.check("…and records that it was cross-checked against the bundle",
                  res.freshness["boundToBundle"] is True, str(res.freshness.keys()))
        rep.check("…and that the shard offset was proved, not assumed",
                  res.freshness["shardOffsetVerified"] is True, str(res.freshness))

    class _BoundToV03:
        """The decision bundle_v03.json would have been signing."""
        subject = decision.subject
        semantic_status = SemanticStatus.PASSED
        reason_codes = decision.reason_codes
        checks = decision.checks
        break_glass = None

        @staticmethod
        def digest():
            return fixtures.fresh_bundle_message_digest_hex()

    from .verifiers import CosignBundleVerifier
    binding = CosignBundleVerifier().verify(_BoundToV03, cfg)
    rep.check("the v0.3 bundle parses but does NOT bind without execution",
              not binding.established and NOT_RUN in binding.reason_codes,
              f"{binding.reason_codes} {binding.detail}")
    rep.check("…and reports NO identity, because a KEYED bundle carries none",
              binding.identity is None,
              "a key proves possession, never who held it — there is no certificate here")

    att = CiAuthorityAdapter(config).attest(_BoundToV03)
    rep.line(f"CI adapter on the v0.3 evidence set -> {att.provenance_status.value} "
             f"{list(att.reason_codes)}")
    rep.check("real binding + real FRESH freshness is STILL not CI_ATTESTED",
              att.provenance_status is ProvenanceStatus.UNAVAILABLE,
              att.provenance_status.value)
    rep.check("…and the refusal names identity as the missing fact",
              R.AUT_IDENTITY_NOT_ESTABLISHED in att.reason_codes, str(att.reason_codes))


def check_version_tiers(rep):
    rep.section("14. version tiers — four provenance situations, none of them UNSTATED")
    reg = shapes.registry()

    rep.check("no shape reports UNSTATED any more", not reg.retired_version_states(),
              "still UNSTATED: " + str(reg.retired_version_states()))
    for shape_id in sorted(reg.entries):
        entry = reg.get(shape_id)
        rep.check(f"{shape_id} names a version tier", bool(entry.version_tier),
                  "an entry with no tier is an entry whose provenance nobody recorded")
        rep.check(f"{shape_id} explains that tier", bool(entry.version_provenance),
                  "a tier without a reason is a label")

    tiers = reg.version_tiers()
    for name, ids in sorted(tiers.items()):
        rep.line(f"{name}: {', '.join(ids)}")

    # RUNNER-RESOLVED is the load-bearing distinction. It must carry the install mechanism and
    # it must NOT carry a version constraint: "we know how it was installed and that mechanism
    # does not pin" is a different state from "nobody told us", and inventing a plausible
    # number to make the column uniform is the fabrication this registry exists to prevent.
    runner = tiers.get("RUNNER-RESOLVED", [])
    rep.check("exactly the three trust-shape captures are RUNNER-RESOLVED",
              sorted(runner) == sorted(["cosign.bundle.keyless.legacy.v1",
                                        "gh.environment.protected.v1",
                                        "oidc.github.claims.v1"]), str(runner))
    for shape_id in runner:
        entry = reg.get(shape_id)
        rep.check(f"{shape_id}: versionConstraint is null",
                  entry.version_constraint is None and not entry.version_is_gateable(),
                  f"a RUNNER-RESOLVED shape may not carry a version range, got "
                  f"{entry.version_constraint!r}")
        rep.check(f"{shape_id}: the install mechanism is recorded",
                  entry.runner_environment == "GitHub-hosted"
                  and entry.cosign_provenance == "sigstore/cosign-installer@v3"
                  and entry.gh_provenance == "ambient runner install",
                  f"{entry.runner_environment}/{entry.cosign_provenance}/{entry.gh_provenance}")
        rep.check(f"{shape_id}: RUNNER-RESOLVED is not spelled UNSTATED",
                  entry.tool_version == "RUNNER-RESOLVED", entry.tool_version)

    # The three gateable tiers must all carry a range, and it must be the one the gate uses.
    for shape_id, expect in (("cosign.version.v1", "v3.1.2"),
                             ("cosign.bundle.keyed.v0_3", "v3.1.2"),
                             ("cosign.bundle.v0_3.keyed", "v3.1.3"),
                             ("cosign.verifyblob.v03.ok.v1", "v3.1.3"),
                             ("rekor.cli.get.v1", "v1.5.3"),
                             ("rekor.cli.loginfo.v1", "v1.5.3"),
                             ("gh.repo.v1", "v2.65.0")):
        entry = reg.get(shape_id)
        rep.check(f"{shape_id} pins {expect}", entry.tool_version == expect, entry.tool_version)
        rep.check(f"{shape_id} carries a gateable range", entry.version_is_gateable(),
                  str(entry.version_constraint))
    rep.check("the gh captures record the release date the operator supplied",
              reg.get("gh.repo.v1").tool_release_date == "2025-01-06",
              reg.get("gh.repo.v1").tool_release_date)

    # CORROBORATION. The gh version was the last claim in the corpus resting on the operator's
    # word alone: no `gh --version` was captured, so "2.65.0, released 2025-01-06" was an
    # assertion with nothing outside this repository to check it against. It now carries a link
    # to the upstream release record. Two things must hold, and the second is the interesting
    # one: every OPERATOR-ASSERTED-CONFIRMED gh entry carries the link, and NO entry in any
    # other tier does — because corroborating that a version exists is not observing the binary
    # that produced the capture, and a link pasted onto a RUNNER-RESOLVED entry would imply a
    # pin that genuinely does not exist.
    gh_confirmed = [s for s in reg.validated_ids()
                    if reg.get(s).tool == "gh"
                    and reg.get(s).version_tier == "OPERATOR-ASSERTED-CONFIRMED"]
    rep.check("every OPERATOR-ASSERTED-CONFIRMED gh shape carries a corroboration link",
              bool(gh_confirmed) and all(
                  reg.get(s).version_corroboration
                  == "https://github.com/cli/cli/releases/tag/v2.65.0" for s in gh_confirmed),
              str([(s, reg.get(s).version_corroboration) for s in gh_confirmed]))
    stray = [s for s in sorted(reg.entries)
             if reg.get(s).version_corroboration
             and reg.get(s).version_tier != "OPERATOR-ASSERTED-CONFIRMED"]
    rep.check("no shape outside OPERATOR-ASSERTED-CONFIRMED claims corroboration",
              not stray, str(stray))
    rep.check("corroboration did NOT promote the gh tier to OBSERVED-CAPTURE",
              all(reg.get(s).version_tier == "OPERATOR-ASSERTED-CONFIRMED"
                  for s in gh_confirmed),
              "a release record proves the version exists, not that it produced this capture")

    # Both cosign versions really do pass the gate, and the corpus proves both.
    for name, expect in (("cosign_version.json", "v3.1.2"),
                         ("cosign_version_3_1_3.json", "v3.1.3")):
        res = cosign.parse_version(fixtures.load_normalized(name))
        rep.check(f"{name} parses and reports {expect}",
                  res.ok and res.data["version"] == expect,
                  f"{res.reason_code}: {res.detail}" if not res.ok else res.data["version"])
    supported, code, _ = cosign.VERSION_GATE.check("v3.1.3")
    rep.check("the cosign gate accepts v3.1.3", supported, str(code))
    rep.check("the gate's `validated` string names BOTH observed versions",
              "3.1.2" in cosign.VERSION_GATE.validated
              and "3.1.3" in cosign.VERSION_GATE.validated,
              cosign.VERSION_GATE.validated)

    # SERVER-API and NOT-CAPTURED are honest states too, and neither may be gated.
    for shape_id in ("rekor.rest.entry.v1", "rekor.rest.entry.fresh.v1",
                     "rekor.rest.loginfo.v1"):
        entry = reg.get(shape_id)
        rep.check(f"{shape_id} is SERVER-API with no client version to gate",
                  entry.version_tier == "SERVER-API" and entry.version_constraint is None,
                  f"{entry.version_tier}/{entry.version_constraint}")
    blocked = reg.get("cosign.bundle.keyless.v0_3")
    rep.check("the BLOCKED keyless shape is NOT-CAPTURED, which is not UNSTATED either",
              blocked.version_tier == "NOT-CAPTURED"
              and blocked.tool_version == "NOT-CAPTURED", blocked.version_tier)


def check_keyless_v03_still_blocked(rep):
    rep.section("15. the v0.3 KEYLESS bundle: still BLOCKED, with the receipt")
    reg = shapes.registry()
    entry = reg.get("cosign.bundle.keyless.v0_3")

    rep.check("cosign.bundle.keyless.v0_3 is BLOCKED", entry.status == shapes.BLOCKED,
              entry.status)
    rep.check("the captured v0.3 bundle is KEYED, not keyless",
              cosign.parse_bundle(fixtures.load_normalized("bundle_v03.json"),
                                  cosign_version="v3.1.3").data["keyless"] is False,
              "bundle_v03.json carries publicKey.hint, not a Fulcio certificate")

    # The impossibility evidence: digest-pinned in SHAPES.json and re-hashed at load, like any
    # capture. It validates NOTHING — a blocked entry has nothing to validate — and the point
    # of pinning it is that a blocked shape's stated reason should not degrade into hearsay.
    rep.check("keyless_attempt.txt is pinned as blockedEvidence",
              isinstance(entry.blocked_evidence, dict)
              and entry.blocked_evidence.get("captureFile") == fixtures.KEYLESS_ATTEMPT_FILE,
              str(entry.blocked_evidence))
    rep.check("…and its digest re-verifies at load", not entry.blocked_evidence_problem,
              entry.blocked_evidence_problem)
    text = fixtures.load_text(fixtures.KEYLESS_ATTEMPT_FILE)
    rep.check("…and it says what the blockedReason claims it says",
              fixtures.KEYLESS_ATTEMPT_MARKER in text, repr(text[:200]))
    rep.line("keyless_attempt.txt: " + " / ".join(
        ln.strip() for ln in text.splitlines() if ln.strip()))
    rep.check("the blockedReason names the OIDC device flow as the blocker",
              "device-code" in entry.blocked_reason or "OIDC" in entry.blocked_reason,
              entry.blocked_reason[:200])

    # Tampering with the evidence must be visible in the refusal, and must not unblock anything.
    tampered = shapes.ShapeEntry("fake-blocked", {
        "status": "BLOCKED", "provenance": "NONE", "blockedReason": "no capture exists",
        "blockedEvidence": {"captureFile": fixtures.KEYLESS_ATTEMPT_FILE,
                            "captureSha256": "0" * 64}})
    tampered._resolve()
    rep.check("altered blockedEvidence is reported in the refusal, and still refuses",
              tampered.status == shapes.BLOCKED
              and "blockedEvidence unverified" in tampered.blocked_reason,
              tampered.blocked_reason)
    promoted = shapes.ShapeEntry("fake-promote", {
        "status": "VALIDATED", "provenance": "REAL_CAPTURE",
        "captureFile": fixtures.KEYLESS_ATTEMPT_FILE,
        "captureSha256": _digest_of_capture(fixtures.KEYLESS_ATTEMPT_FILE),
        "schemaFile": "cosign_bundle_keyless.schema.json"})
    promoted._resolve()
    res = shapes.validate_shape(json.loads(fixtures.load_text("bundle_v03.json")),
                                "cosign.bundle.keyless.v0_3")
    rep.check("evidence of IMPOSSIBILITY cannot be turned into evidence of a SHAPE",
              not res[0] and res[1] == R.AUT_OUTPUT_SHAPE_UNKNOWN,
              "a real v0.3 document validated against the blocked keyless schema")
    rep.line("(a hand-made entry CAN pin keyless_attempt.txt as a captureFile and go VALIDATED "
             f"[{promoted.status}] — the loader checks digests, not meaning. What stops the "
             "shipped manifest doing that is that the schema would not match and the parser "
             "would refuse anyway; the file is registered as blockedEvidence, never as a "
             "captureFile.)")


def check_four_reasons(rep):
    rep.section("16. of the four reasons no shipped capture can produce a real CI_ATTESTED, "
                "how many remain")
    decision = make_decision()

    # (a) SANITIZED JSON vs UNSANITIZED CERT SAN. Walk it: the ONLY identity-bearing capture in
    #     the corpus is the legacy keyless bundle, and its certificate names the pre-sanitisation
    #     repository.
    keyless = cosign.parse_bundle(fixtures.load_normalized("cosign_keyless_bundle.json"))
    claims = oidc.parse_claims(fixtures.load_normalized("oidc_claims.json")).data["claims"]
    check = cosign.check_certificate_identity(keyless.data, expected_repository=None,
                                              claims=claims)
    a_open = (not check.ok) and check.reason_code == R.AUT_BINDING_MISMATCH
    rep.check("(a) sanitized JSON vs unsanitized cert SAN — STILL OPEN", a_open,
              "the identity check no longer disagrees; if that is because it was relaxed, "
              "that is a regression")
    v03_keyless = cosign.parse_bundle(fixtures.load_normalized("bundle_v03.json"),
                                      cosign_version="v3.1.3").data["keyless"]
    rep.check("(a) the new v0.3 capture does not help: it is KEYED and has no certificate",
              v03_keyless is False, "bundle_v03.json is keyless?")
    rep.line("(a) OPEN, and more precisely than the original framing. The 2026-08-06 round "
             "contains no certificate at all, so it cannot supply an unsanitized identity. "
             f"cert says {check.data['certificateRepository']!r}, claims say "
             f"{claims['repository']!r}.")
    # PRECISION. (a) is a CORPUS defect, not an absolute code-path blocker: it bites whenever
    # the sanitized claim set is configured or the sanitized name is the decision subject. Take
    # the certificate at its word — subject = the repository the DER names, claim set omitted —
    # and identity establishes. Recording that is the difference between "(a) blocks
    # CI_ATTESTED" and "(a) blocks CI_ATTESTED unless you trust the cert alone", and only the
    # second is true.
    unblocked = cosign.check_certificate_identity(
        keyless.data, expected_repository=fixtures.CERT_REPOSITORY, claims=None)
    rep.check("(a) …but taking the certificate at its word, identity DOES check out",
              unblocked.ok, f"{unblocked.reason_code}: {unblocked.detail}"
              if not unblocked.ok else "")
    rep.line("(a) so (a) is a defect of the CORPUS (a sanitized capture), not of the code "
             "path: omit the contradicting claim set and use the repository the certificate's "
             "signed DER actually names, and the identity fact is established. That is what "
             "the best-case run below does.")

    # (b) NO FRESH REST ENTRY BOUND TO A BUNDLE. Walk it.
    bundle = cosign.parse_bundle(fixtures.load_normalized("bundle_v03.json"),
                                 cosign_version="v3.1.3").data
    entry = rekor.parse_rest_entry(
        fixtures.load_normalized("rekor_rest_entry_fresh.json")).data
    bound = cosign.check_tlog_agreement(bundle, entry)
    fresh = rekor.freshness(entry, 3600, now=fixtures.FRESH_INTEGRATED_AT + 60)
    rep.check("(b) a proof-carrying REST entry BOUND to a corpus bundle — CLOSED as stated",
              bound.ok and fresh.ok and bound.data["sameLoggedBody"] is True,
              f"{bound.reason_code} / {fresh.reason_code}")
    rep.line("(b) CLOSED as literally stated, with two caveats recorded rather than skipped. "
             "First: the entry is genuinely bound (byte-identical logged body) and the "
             "freshness verifier accepts it inside the window — but it is PERISHABLE, so it "
             "proves the verifier works on a bound entry, not that a shipped capture stays "
             "fresh.")
    # Second caveat, and the one that decides item 7: the bound entry belongs to a KEYED
    # bundle, which supplies no identity. The version of (b) that CI_ATTESTED actually needs —
    # a fresh REST entry bound to the IDENTITY-BEARING bundle — is still open, and the kit
    # refuses the obvious shortcut of pairing the fresh entry with the other bundle.
    cross = cosign.check_tlog_agreement(keyless.data, entry)
    rep.check("(b) the fresh entry cannot be borrowed by the identity-bearing bundle",
              not cross.ok, "the legacy keyless bundle appears to share this log entry")
    rep.line(f"(b) second caveat: pairing the fresh entry with the KEYLESS bundle -> "
             f"{cross.reason_code}. Identity and fresh transparency evidence live in DIFFERENT "
             "captures and the kit refuses to combine them, so the useful form of (b) is "
             "still OPEN.")

    # (c) BOTH CAPTURED ENVIRONMENTS REFUSED AS PRINCIPALS.
    refused = []
    for name in ("env_one.json", "env_protected_one.json"):
        qualifies, code, _ = gh.is_qualifying_environment(fixtures.load_normalized(name))
        refused.append(qualifies is False and code == R.AUT_PRINCIPAL_NOT_DISTINCT)
    rep.check("(c) both captured environments still refused as principals — STILL OPEN",
              all(refused), str(refused))
    rep.line("(c) OPEN — and it never bore on CI_ATTESTED in the first place. `principal` is "
             "only in the INDEPENDENTLY_ATTESTED rule (contracts.RULES); CI_ATTESTED requires "
             "identity+binding+freshness. It blocks the higher award, not this one.")

    # (d) THE OIDC TOKEN'S WINDOW EXPIRED. Walk the actual code path.
    ok_now, code_now, why_now = oidc.check_claims(claims, at_time=None)
    ok_then, code_then, why_then = oidc.check_claims(
        claims, at_time=fixtures.KEYLESS_SIGNED_AT)
    rep.check("(d) the claim set IS expired against a real clock", not ok_now,
              "the recorded 5-minute token appears live, which cannot be right")
    rep.check("(d) …but the verifier judges it at the moment of SIGNING, where it was live — "
              "CLOSED BY DESIGN", ok_then, f"{code_then}: {why_then}")
    rep.line(f"(d) CLOSED. CosignBundleVerifier._claims passes at_time=integratedTime "
             f"({fixtures.KEYLESS_SIGNED_AT}), not now; against 'now' the token gives "
             f"{code_now}. Judging an archived token against the current clock would reject "
             "every recorded token ever written, which is strictness that means nothing.")

    # The end-to-end consequence, from the adapters rather than from prose.
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory(prefix="shipgate-four-reasons-") as tmp:
        for name in fixtures.CAPTURE_FILES:
            shutil.copy(fixtures.normalized_path(name), os.path.join(tmp, name))
        # The strongest evidence set the corpus can assemble: the identity-bearing keyless
        # bundle with the contradicting sanitized claim set left OUT (that is reason (a) at its
        # most generous), plus the freshest transparency evidence that bundle can honestly use.
        raw = fixtures.keyless_config(directory=tmp, freshness_max_age_seconds=604800)
        raw.pop("oidc")
        att = CiAuthorityAdapter(raw).attest(_KeylessBound())
        rep.line(f"best-case CI adapter -> {att.provenance_status.value} "
                 f"{list(att.reason_codes)}")
        rep.check("even the best evidence set the corpus can assemble is not CI_ATTESTED",
                  att.provenance_status is ProvenanceStatus.UNAVAILABLE,
                  att.provenance_status.value)
        # WHICH FACT IS MISSING is the whole answer, so it is read off the attestation rather
        # than off the reason codes. (AUT_IDENTITY_NOT_ESTABLISHED is present in the codes —
        # the OIDC verifier always refuses — but the cosign verifier DID establish identity,
        # and `evaluate` only drops contradicted codes when a rule is actually awarded.)
        rep.check("identity is NOT established from an unverified certificate",
                  att.identity is None, str(att.identity))
        rep.check("binding is NOT established without cosign", att.binding is None,
                  str(att.binding))
        rep.check("FRESHNESS is the missing fact — the identity-bearing bundle has no REST "
                  "entry of its own in the corpus", att.freshness is None, str(att.freshness))

        # And the shortcut is closed end to end, not only at the parser: pointing this evidence
        # set at the FRESH entry substitutes an unrelated log record, and the rekor-cli
        # corroboration catches it.
        swapped = dict(raw, rekor=dict(raw["rekor"], restEntry="rekor_rest_entry_fresh.json"))
        att2 = CiAuthorityAdapter(swapped).attest(_KeylessBound())
        rep.check("substituting the fresh entry into the identity evidence set is REFUSED",
                  att2.provenance_status is ProvenanceStatus.UNAVAILABLE
                  and R.AUT_BINDING_MISMATCH in att2.reason_codes, str(att2.reason_codes))
        rep.line("substituting the fresh (unrelated) entry -> "
                 f"{att2.provenance_status.value} {list(att2.reason_codes)}: the corroborating "
                 "rekor-cli record names logIndex 1000000 and the substituted REST entry names "
                 "2354787700, so the two sources contradict and the run refuses.")

    rep.line("ANSWER: 2 of the 4 remain, and neither is the one the original framing pointed "
             "at. (a) OPEN as a corpus defect but NOT the CI_ATTESTED blocker — trust the "
             "certificate alone and identity establishes. (b) CLOSED as stated, but only for "
             "the KEYED bundle, which carries no identity; the useful form — a fresh entry "
             "bound to the IDENTITY-bearing bundle — is OPEN and is now the SOLE blocker of "
             "CI_ATTESTED. (c) OPEN, and it never bore on CI_ATTESTED: it blocks "
             "INDEPENDENTLY_ATTESTED. (d) CLOSED by design, and already was: token liveness is "
             "judged at integratedTime.")


class _KeylessBound:
    """The decision the captured KEYLESS bundle would have been signing."""
    subject = SubjectIdentity(repository=fixtures.CERT_REPOSITORY, commit="c" * 40,
                              tree_digest="d" * 64)
    semantic_status = SemanticStatus.PASSED
    reason_codes = (R.SEM_ALL_REQUIRED_CHECKS_PASSED,)
    checks = (CheckResult(check_id="wiring.routes", title="every route is served", passed=True,
                          required=True, showstopper=True, evidence_kind="RUNTIME"),)
    break_glass = None

    @staticmethod
    def digest():
        return fixtures.keyless_message_digest_hex()


def _leaf_hash(body: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(b"\x00" + body).digest()


def _sha256(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()


def main():
    rep = Report()
    check_availability(rep)
    check_constants(rep)
    check_positives(rep)
    check_rejections(rep)
    check_failed_decision(rep)
    check_negative_environment(rep)
    check_blocked_shapes(rep)
    check_imports(rep)
    check_rule_table(rep)
    check_end_to_end(rep)
    check_wiring(rep)
    check_keyless_identity_path(rep)
    check_v03_round(rep)
    check_version_tiers(rep)
    check_keyless_v03_still_blocked(rep)
    check_four_reasons(rep)

    print(f"\n{'=' * 70}")
    if rep.failed:
        print(f"FAILED {len(rep.failed)} of {rep.passed + len(rep.failed)} checks:")
        for line in rep.failed:
            print("  x " + line)
        return 1
    print(f"OK — {rep.passed} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
