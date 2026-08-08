#!/usr/bin/env python3
"""ship-gate v4.0 — command line interface.

DELIBERATELY THIN. Every rule lives in the `shipgate` library; this file parses arguments,
calls the library, renders, and picks an exit code. If you find yourself adding a policy
decision here, it belongs in `shipgate/semantic/` instead.

This is also the ONLY module permitted to touch the optional authority kit, and it does so
by probing for it (`shipgate.authority_status()`) rather than importing it at module level.
Delete `shipgate/authority/` and every command below still works; `--authority` then
reports AUTHORITY_UNAVAILABLE instead of raising.

Exit codes (the consumer contract — never grep the outcome string):
    0   VERIFIED / CI_ATTESTED / INDEPENDENTLY_ATTESTED
    1   FAILED
    3   AUTHORITY_UNAVAILABLE
    2   usage / internal error
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shipgate import SKILL_VERSION, authority_status  # noqa: E402
from shipgate.models import reasons as R  # noqa: E402
from shipgate.models.decision import (  # noqa: E402
    EXIT_CODES,
    Outcome,
    ProvenanceStatus,
    SemanticStatus,
    derive_outcome,
)
from shipgate.models.policy import Mode, Policy  # noqa: E402
from shipgate.models.profile import BUILTIN, EscalationSignal  # noqa: E402
from shipgate.reporting import render_html, render_text  # noqa: E402
from shipgate.runner import RunRequest, run as run_gate  # noqa: E402
from shipgate.util.canonical import canonical_bytes, loads_strict  # noqa: E402

USAGE_ERROR = 2


# ---------------------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------------------

def cmd_run(args):
    policy = _policy(args)
    # Parsed BEFORE the run, not after. A usage error in this flag used to surface only once
    # the whole gate had executed — every collector, every browser page, every mutation — and
    # then exit 2 on a typo. An argument the process can reject in a microsecond must not cost
    # the operator a full run to discover.
    required = _required_coverage(getattr(args, "require_coverage", None))
    request = RunRequest(
        repo=args.repo,
        run_area=args.run_area,
        profile_id=args.profile,
        policy=policy,
        run_id=args.run_id,
        round_index=args.round,
        escalation_signals=tuple(_signals(args.escalate)),
        profile_recommendations=tuple(args.recommend_profile or ()),
        artifact_path=args.artifact,
        residual_risk=args.residual_risk or "",
        static_only=args.static_only,
        phase_claims=_phase_claims(args),
        options=_options(args.option, args.options_file),
        allow_env=tuple(args.allow_env or ()),
    )
    result = run_gate(request)
    decision = result.decision

    attestation = None
    prov = ProvenanceStatus.NONE
    if args.authority:
        attestation, prov = _attest(decision, args.authority_config)
    _persist_attestation(result.workdir, decision, attestation, bool(args.authority))

    _emit(decision, attestation, args, result.workdir)

    outcome = derive_outcome(decision.semantic_status, prov)
    code = EXIT_CODES[outcome]

    # OPT-IN coverage enforcement. Note what it keys on: the ABSENCE of corroborated
    # coverage, never the presence of a claim. A team that turns this on gets a stricter
    # contract without any self-reported field becoming load-bearing — writing `"H": "run"`
    # in phases.json still buys nothing, because only a collector can corroborate.
    # Reported whenever it is unmet, escalated only when the run would otherwise have
    # passed. An operator who asked for coverage needs to hear that it was not met even on a
    # run that failed for another reason — otherwise they fix the other reason, re-run, and
    # meet the requirement for the first time by surprise.
    if required:
        cov = decision.coverage
        corroborated = set(cov.corroborated()) if cov is not None else set()
        missing = [p for p in required if p not in corroborated]
        if missing:
            from shipgate.semantic.engine import PHASE_EVIDENCE
            hints = {
                "A2": "requirements.json (assets/templates/requirements.json.template)",
                "G2": "design-tokens.json "
                      "(assets/templates/design-tokens.json.template) plus a UI crawl",
                "G3": "a UI crawl covering at least two surfaces",
                "H": "adversarial-config.json "
                     "(assets/templates/adversarial-config.json.template)",
            }
            print(f"\n--require-coverage: {', '.join(missing)} was not corroborated by a "
                  f"collector. The decision is unchanged and still records {outcome.value}; "
                  f"this flag only changes whether THIS PROCESS blocks.", file=sys.stderr)
            for phase in missing:
                kind = PHASE_EVIDENCE.get(phase)
                print(f"  {phase}: corroborated by the "
                      f"{kind.value if kind else 'n/a'} collector — needs "
                      f"{hints.get(phase, 'its collector inputs')}", file=sys.stderr)
            if code == 0:
                code = 1

    # MODE affects ENFORCEMENT, never the decision. The decision on disk is identical in all
    # three modes — the same evidence reaches the same semantic status and the same digest.
    # What changes is whether this process blocks the caller, which is what makes staged
    # adoption (advisory -> observe -> enforce) possible without ever softening a verdict.
    if policy.mode in (Mode.ADVISORY, Mode.OBSERVE) and code != 0:
        print(f"\nmode={policy.mode.value}: the outcome is {outcome.value} (enforcing exit "
              f"code would be {code}); exiting 0 because this mode is NON-BLOCKING. The "
              f"decision itself is unchanged and still records {outcome.value}.",
              file=sys.stderr)
        return 0
    return code


def cmd_verdict(args):
    """Re-derive the outcome from a decision that is already on disk.

    Useful in CI: the collecting job publishes decision.json, and a later job decides. The
    decision is re-read and re-digested, so a decision edited in transit is rejected rather
    than trusted.

    A PROVENANCE STATUS IS NEVER READ. This function used to take `provenanceStatus` from an
    `attestation.json` sidecar, or from an `attestation` key on the envelope, and return it as
    the run's provenance. External audit turned that into a two-field forgery: writing
    `{"decisionDigest": "<the real digest>", "provenanceStatus": "INDEPENDENTLY_ATTESTED"}`
    beside a PASSED decision produced `outcome: INDEPENDENTLY_ATTESTED`, exit 0, with no
    signature, no OIDC identity, no cosign evidence, no distinct principal and no attestation
    body. The envelope variant was worse still: the digest covers the `decision` key only, so
    an `attestation` key appended to a valid envelope survived the tamper check without even
    naming a digest.

    The digest check was never the problem. Binding proves a record NAMES this decision; it
    proves nothing about whether anybody verified it. So the rule is now the same one the rest
    of this product applies to unverifiable input: a claim may only ever SUBTRACT. Provenance
    is re-established by running the authority kit against the raw evidence — `--authority-config`
    here, or `gate.py attest` beforehand — or it is `NONE`, with `AUT_RECORD_NOT_REVERIFIED`
    recording that a record was present and was not believed.
    """
    body, actual = _read_decision_envelope(args.decision)
    semantic = SemanticStatus(body["semanticStatus"])

    prov = ProvenanceStatus.NONE
    notes = []
    codes = []

    # A record may be PRESENT. It is never an INPUT to the status.
    record = _find_provenance_record(Path(args.decision), actual)
    if record is not None:
        codes.append(R.AUT_RECORD_NOT_REVERIFIED)
        notes.append(
            f"a provenance record was found ({record['source']}) claiming "
            f"{record['claimed'] or 'an unspecified status'}. It was NOT believed: a status "
            "on disk is a claim, not evidence. Re-run it with "
            "`--authority-config <config.json>`, or attest beforehand with `gate.py attest`.")

    if getattr(args, "authority_config", None):
        # RE-ESTABLISH. The decision is rebuilt from the published bytes and re-attested
        # against the raw evidence; the gate is NOT re-run, so the digest the adapter sees is
        # the digest that was signed.
        decision = _rehydrate(body)
        rebuilt = decision.digest()
        if rebuilt != actual:
            _fail(f"rehydrated decision digest {rebuilt} does not match the envelope's "
                  f"{actual}; refusing to attest a decision this build cannot reproduce.",
                  code=1)
        attestation, prov = _attest(decision, args.authority_config)
        if attestation is not None:
            codes.extend(c for c in attestation.reason_codes if c not in codes)
            if R.AUT_RECORD_NOT_REVERIFIED in codes and prov in (
                    ProvenanceStatus.CI_ATTESTED, ProvenanceStatus.INDEPENDENTLY_ATTESTED):
                codes.remove(R.AUT_RECORD_NOT_REVERIFIED)
                notes = [n for n in notes if "was NOT believed" not in n]
            notes.append(f"re-verified by {attestation.verifier} "
                         f"{attestation.verifier_version}: {attestation.detail[:200]}")

    outcome = derive_outcome(semantic, prov)
    coverage_suffix = _coverage_suffix(body)
    summary = {
        "decisionDigest": actual,
        "semanticStatus": semantic.value,
        "provenanceStatus": prov.value,
        "outcome": outcome.value,
        # RECOMPUTED, not read. The stored `displayOutcome` was written when the decision was
        # produced and knows nothing about the provenance re-derived here; echoing it made the
        # forged output self-contradictory, printing `outcome: INDEPENDENTLY_ATTESTED` beside
        # `displayOutcome: VERIFIED — partial coverage`.
        "displayOutcome": (f"{outcome.value} — {coverage_suffix}" if coverage_suffix
                           else outcome.value),
        "exitCode": EXIT_CODES[outcome],
        "reasonCodes": codes,
        "provenanceNotes": notes,
    }
    cov = body.get("coverage") if isinstance(body.get("coverage"), dict) else None
    if cov is not None:
        summary["coverage"] = {
            "trustClass": cov.get("trustClass"),
            "coverageComplete": cov.get("coverageComplete"),
            "declaredNotRun": cov.get("declaredNotRun"),
            "uncorroboratedClaims": cov.get("uncorroboratedClaims"),
            "corroborated": cov.get("corroborated"),
        }
    print(json.dumps(summary, indent=2))
    return EXIT_CODES[outcome]


def cmd_attest(args):
    """Attest a decision that ALREADY EXISTS, without re-running the semantic gate.

    This command exists because both shipped reference workflows were wrong in the same way,
    and the shape of the error is worth stating: they ran the gate, signed the resulting
    decision, and then ran the gate AGAIN to attach the attestation. Two evaluations of
    identical evidence produce different `decisionId` and `createdAt` values and therefore
    different digests, so the second run's decision could never bind to the first run's
    signature. The workflow's own artifact was overwritten by the unsigned one on the way past.

    A decision is an immutable artifact. Attesting it must READ it, never reproduce it. So:
    rehydrate the published bytes, assert the rebuilt digest equals the published digest,
    hand THAT decision to the authority kit, and construct an `AttestedDecision` so the model
    guards fire — non-AUT reason codes refused, non-binding digest refused, FAILED refused.
    """
    body, actual = _read_decision_envelope(args.decision)
    decision = _rehydrate(body)
    rebuilt = decision.digest()
    if rebuilt != actual:
        _fail(f"rehydrated decision digest {rebuilt} does not match the envelope's {actual}; "
              "refusing to attest a decision this build cannot reproduce.", code=1)

    attestation, prov = _attest(decision, args.authority_config)
    out = Path(args.out) if args.out else Path(args.decision).parent / "attestation.json"
    record = {
        "schema": "shipgate.attestation-record/1",
        "decisionDigest": actual,
        "authorityRequested": True,
        "provenanceStatus": (attestation.provenance_status.value if attestation
                             else ProvenanceStatus.UNAVAILABLE.value),
        "attestation": attestation.to_json() if attestation else None,
        "note": ("The decision is unchanged by this record. This record is NOT itself trusted "
                 "by `gate.py verdict`: re-verify with `verdict --authority-config`. A status "
                 "in a file is a claim, not evidence."),
    }
    out.write_bytes(canonical_bytes(record))
    outcome = derive_outcome(decision.semantic_status, prov)
    print(json.dumps({
        "decisionDigest": actual,
        "semanticStatus": decision.semantic_status.value,
        "provenanceStatus": prov.value,
        "outcome": outcome.value,
        "reasonCodes": list(attestation.reason_codes) if attestation else [R.AUT_KIT_ABSENT],
        "detail": attestation.detail if attestation else "the authority kit is not installed",
        "record": str(out),
    }, indent=2))
    return EXIT_CODES[outcome]


def _read_decision_envelope(path_str):
    """(body, digest). Refuses anything that is not a self-consistent envelope."""
    path = Path(path_str)
    try:
        doc = loads_strict(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        _fail(f"cannot read {path}: {type(exc).__name__}: {exc}")
    if not isinstance(doc, dict):
        _fail(f"{path} is not a decision envelope")
    body = doc.get("decision")
    claimed = doc.get("decisionDigest")
    if body is None or claimed is None:
        _fail(f"{path} is not a decision envelope (needs 'decision' and 'decisionDigest')")
    from shipgate.util.canonical import digest_of
    actual = digest_of(body)
    if actual != claimed:
        _fail(f"decision digest mismatch: envelope claims {claimed}, content hashes to "
              f"{actual}. The decision was modified after it was produced.", code=1)
    return body, actual


def _find_provenance_record(decision_path, digest):
    """Locate a provenance record without believing any of it.

    Both places a forgery was demonstrated are checked, and BOTH are reported rather than
    consumed: the `attestation` key on the envelope (which the decision digest does not
    cover, so it survives the tamper check) and an `attestation.json` sitting beside the
    decision. `claimed` is echoed back to the operator purely so the output names what was
    ignored.
    """
    try:
        doc = loads_strict(decision_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        doc = {}
    embedded = doc.get("attestation") if isinstance(doc, dict) else None
    if isinstance(embedded, dict):
        return {"source": "an `attestation` key inside the envelope, which the decision "
                          "digest does not cover",
                "claimed": embedded.get("provenanceStatus")}
    sidecar = decision_path.parent / "attestation.json"
    if sidecar.exists():
        try:
            rec = loads_strict(sidecar.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            rec = None
        if isinstance(rec, dict):
            return {"source": f"the sidecar {sidecar.name}"
                              + ("" if rec.get("decisionDigest") == digest
                                 else " (which does not even bind to this decision)"),
                    "claimed": rec.get("provenanceStatus")}
    return None


def _coverage_suffix(body):
    cov = body.get("coverage")
    if not isinstance(cov, dict):
        return ""
    stored = body.get("displayOutcome")
    if isinstance(stored, str) and " — " in stored:
        return stored.split(" — ", 1)[1]
    return ""


def cmd_report(args):
    path = Path(args.decision)
    doc = loads_strict(path.read_text(encoding="utf-8"))
    decision = _rehydrate(doc["decision"])
    out = Path(args.out)
    out.write_text(render_html(decision), encoding="utf-8")
    print(f"wrote {out}")
    return 0


def cmd_profiles(args):
    if args.show:
        prof = BUILTIN.get(args.show)
        if prof is None:
            _fail(f"unknown profile {args.show!r}; known: {sorted(BUILTIN)}")
        print(json.dumps(prof.to_json(), indent=2))
        return 0
    for pid, prof in sorted(BUILTIN.items(), key=lambda kv: kv[1].rank):
        print(f"{pid:10s} rank={prof.rank:<4d} digest={prof.digest()[:16]}  {prof.title}")
        print(f"           {prof.description}")
    return 0


def _phase_checker_admissions():
    """Run every phase collector's fail-first admission and report all four uniformly.

    Each entry answers the only question that matters before a run: does this instrument
    catch a seeded instance of each defect class it claims, and does it stay silent on a
    correct reference? A checker that is not admitted cannot clear its phase's caveat —
    the semantic layer refuses it — so surfacing the state here is not decoration.

    Never raises: a checker that blows up during its own admission is reported as
    `admitted: false` with the exception, because a doctor that dies is worse than a
    doctor that says the instrument is broken.
    """
    from shipgate.models.evidence import EvidenceKind

    def _safe(fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            return {"admitted": False, "defectClasses": [], "caught": [],
                    "missed": [], "detail": f"{type(exc).__name__}: {exc}"}

    def _entries():
        from shipgate.collectors.adversarial import admission as h_adm
        from shipgate.collectors.requirements import admission as a2_adm
        from shipgate.collectors.conformance import (conformance_admission,
                                                     cross_surface_admission)
        yield "A2", EvidenceKind.REQUIREMENTS, a2_adm
        yield "G2", EvidenceKind.DESIGN_CONFORMANCE, conformance_admission
        yield "G3", EvidenceKind.CROSS_SURFACE, cross_surface_admission
        yield "H", EvidenceKind.ADVERSARIAL_PROBE, h_adm

    out = {}
    for phase, kind, fn in _entries():
        adm = _safe(fn)
        # The four admissions do not share a false-alarm key name, because each names the
        # reference it stayed silent on. Collapse to a count so `doctor` output is uniform,
        # and keep `detail` for the specifics.
        false_alarms = 0
        for key, value in adm.items():
            if key.startswith("falseAlarms"):
                false_alarms = len(value) if isinstance(value, (list, tuple)) else int(value)
        out[phase] = {
            "evidenceKind": kind.value,
            "admitted": bool(adm.get("admitted")),
            "defectClasses": list(adm.get("defectClasses", ())),
            "defectClassCount": len(adm.get("defectClasses", ())),
            "caught": list(adm.get("caught", ())),
            "missed": list(adm.get("missed", ())),
            "falseAlarmsOnCorrectReference": false_alarms,
            "detail": adm.get("detail", ""),
        }
    out["allAdmitted"] = all(v["admitted"] for k, v in out.items() if k != "allAdmitted")
    return out


def _live_field_check(args):
    """Make ONE real GitHub observation and report exactly what came back.

    WHY THIS EXISTS. The principal fact is the only thing separating CI_ATTESTED from
    INDEPENDENTLY_ATTESTED, and it is established by reading GitHub live. That path is
    unit-proven against an injected transport and was never exercised against real GitHub in
    the environment that built this release — the build sandbox cannot reach GitHub's
    repository endpoints. Shipping that as a paragraph of caveat puts the burden on a reader
    who has no way to discharge it.

    So the burden moves into a command. This performs the same call the verifier performs,
    with the same code, and prints the result — including the failure, in full, when it
    fails. It awards nothing and writes nothing: a diagnostic that could contribute to an
    outcome would be a new way to launder a claim.
    """
    import os
    out = {"attempted": True, "awards": "nothing — this is a diagnostic, not evidence"}
    try:
        from shipgate.authority import live
    except ImportError as exc:
        return {"attempted": False, "reason": f"authority kit absent: {exc}"}

    usable, detail = live.available()
    out["tokenPresent"] = usable
    out["tokenDetail"] = detail
    repo = (args.live_repo or os.environ.get("SHIPGATE_LIVE_REPO", "")).strip()
    environment = (args.live_environment
                   or os.environ.get("SHIPGATE_LIVE_ENVIRONMENT", "")).strip()
    out["repository"] = repo
    out["environment"] = environment
    if not repo or not environment:
        out["result"] = "NOT ATTEMPTED"
        out["detail"] = ("--live needs a repository and an environment. Pass --live-repo "
                         "owner/repo and --live-environment NAME, or set SHIPGATE_LIVE_REPO "
                         "and SHIPGATE_LIVE_ENVIRONMENT.")
        return out
    if not usable:
        out["result"] = "BLOCKED"
        out["detail"] = detail
        return out

    try:
        observation = live.observe_environment(repo, environment)
    except live.Blocked as exc:
        out["result"] = "BLOCKED"
        out["detail"] = str(exc)
        return out
    except live.LiveObservationError as exc:
        out["result"] = "FAILED"
        out["detail"] = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 - a diagnostic must not take doctor down
        out["result"] = "ERROR"
        out["detail"] = f"{type(exc).__name__}: {exc}"
        return out

    from shipgate.authority.parsers import gh as gh_parser
    env_body = observation["environment"]["body"]
    qualifies, code, why = gh_parser.is_qualifying_environment(json.dumps(env_body))
    out["result"] = "OBSERVED"
    out["httpStatus"] = observation["environment"]["httpStatus"]
    out["requestId"] = observation["environment"]["requestId"]
    out["bodySha256"] = observation["environment"]["bodySha256"]
    out["apiDate"] = observation["environment"]["apiDate"]
    # The POLICY answer, reported separately from the OBSERVATION, because they are
    # different questions and collapsing them is how "we read a file" became "a principal
    # exists" in the first place.
    out["wouldQualifyAsPrincipal"] = bool(qualifies)
    out["policyReason"] = code or ""
    out["policyDetail"] = why
    if not qualifies:
        out["detail"] = ("GitHub answered, and this environment does NOT constitute an "
                         "independent principal. That is a working live path reporting a "
                         "real answer, not a failure of the path.")
    else:
        out["detail"] = ("GitHub answered and this environment WOULD qualify. An actual "
                         "attestation additionally needs a signed verifier identity; see "
                         "references/authority-kit.md §6a.")
    return out


def cmd_observe(args):
    """PHASE 1 of two-phase attestation: look at GitHub, and write down what was seen.

    Splitting observation from attestation exists to close the one gap the single-phase flow
    cannot: a verifier cannot sign the bytes GitHub returned before it has asked. So phase 1
    asks, records the answer, and emits a challenge committing to it. The verifier signs that
    challenge with its own identity. Phase 2 (`attest --authority-config`, with
    `verifier.observation` pointing here) verifies the signature and only then uses the
    recording.

    The recording is a file, and this kit refuses operator-supplied files as principals. The
    difference is the signature: every field of the observation is covered by a digest inside
    the signed challenge, so an edited recording fails verification. A file nobody signed and
    a file the verifier signed are not the same object.

    This command AWARDS NOTHING. It writes two files and exits.
    """
    from shipgate.authority import live

    # Same discipline as `attest`: read the PUBLISHED bytes and refuse to proceed if this
    # build cannot reproduce their digest. An observation recorded against a decision we
    # could not rebuild would bind to nothing.
    body, actual = _read_decision_envelope(args.decision)
    decision = _rehydrate(body)
    rebuilt = decision.digest()
    if rebuilt != actual:
        _fail(f"rehydrated decision digest {rebuilt} does not match the envelope's {actual}; "
              "refusing to record an observation against a decision this build cannot "
              "reproduce.", code=1)

    usable, detail = live.available()
    if not usable:
        _fail(f"cannot observe: {detail}")
    try:
        observation = live.observe_environment(
            args.repo, args.environment,
            run_id=args.run_id or "", commit=decision.subject.commit or "")
    except live.Blocked as exc:
        print(f"gate.py: BLOCKED: {exc}", file=sys.stderr)
        return 3
    except live.LiveObservationError as exc:
        _fail(str(exc))

    written = live.write_observation(observation, decision, args.out,
                                     run_id=args.run_id or "",
                                     external_time=args.external_time,
                                     run_attempt=args.run_attempt or "")
    print(json.dumps({
        "schema": "shipgate.authority.observe/1",
        "observationPath": written["observationPath"],
        "challengePath": written["challengePath"],
        "challengeSha256": written["challengeSha256"],
        "decisionDigest": decision.digest(),
        "repository": args.repo,
        "environment": args.environment,
        "httpStatus": observation["environment"]["httpStatus"],
        "nextStep": (
            f"sign {written['challengePath']} as the VERIFIER, then attest with "
            f"verifier.observation={written['observationPath']} and verifier.bundle=<bundle>"),
        "awards": "nothing — phase 1 records an observation, it does not attest",
    }, indent=2))
    return 0


#: verify-bundle's exit-code contract. DISTINCT codes on purpose — a consumer must be able
#: to tell "authoritatively verified" from "valid evidence, no current authority" from
#: "verification failed" from "could not check" without grepping strings.
VERIFY_BUNDLE_EXITS = {
    "AUTHORITATIVE": 0,        # semantic PASSED + INDEPENDENTLY_ATTESTED + live recheck
    "VALID_NOT_AUTHORITATIVE": 3,   # evidence verifies; authority not (re)established
    "VERIFICATION_FAILED": 1,  # something in the bundle is wrong, tampered, or refused
    "BLOCKED": 4,              # external verification impossible here (tool/network)
    "INVALID_INPUT": 2,        # not an evidence bundle at all
}


def cmd_verify_bundle(args):
    """Verify a persisted evidence bundle with the SAME engine that produced it.

    NOT A SECOND IMPLEMENTATION, and that is the whole design: this command rehydrates the
    published decision, refuses anything whose digest does not recompute, re-hashes the
    bundled artifact when one is present, and then hands the decision to the ordinary
    authority adapters (`_attest`) with the bundle's own authority config — the exact code
    path `gate.py run --authority` and `gate.py attest` use. Everything the engine enforces
    (builder attestation, external policy, verifier authorization, principal separation,
    deployment approval, external freshness, signatures and transparency evidence, the
    two-phase body digests) is therefore enforced here by construction, and a check added to
    the engine is a check added to this command with no further work.

    WHAT "AUTHORITATIVE" MEANS in the output: the semantic decision PASSED, the authority
    engine re-established INDEPENDENTLY_ATTESTED from the bundle's evidence, AND current
    external state was rechecked live in THIS invocation. Historical validity alone —
    everything verifies but no live recheck happened — is reported truthfully as
    authoritative: false with a human verdict that deliberately does not begin with "PASS".
    """
    directory = Path(args.directory)
    if not directory.is_dir():
        print(json.dumps({"error": f"{directory} is not a directory"}), file=sys.stderr)
        return VERIFY_BUNDLE_EXITS["INVALID_INPUT"]
    decision_path = directory / "decision.json"
    if not decision_path.is_file():
        print(json.dumps({"error": f"{decision_path} does not exist; an evidence bundle "
                                   f"carries the decision envelope it attests"}),
              file=sys.stderr)
        return VERIFY_BUNDLE_EXITS["INVALID_INPUT"]

    # 1. Envelope integrity + rehydration. Tamper maps to VERIFICATION_FAILED, unreadable
    #    input to INVALID_INPUT — a consumer must be able to tell those apart.
    try:
        doc = loads_strict(decision_path.read_text(encoding="utf-8"))
        body, claimed = doc.get("decision"), doc.get("decisionDigest")
        if body is None or claimed is None:
            print(json.dumps({"error": "not a decision envelope (needs 'decision' and "
                                       "'decisionDigest')"}), file=sys.stderr)
            return VERIFY_BUNDLE_EXITS["INVALID_INPUT"]
        from shipgate.util.canonical import digest_of
        actual = digest_of(body)
        if actual != claimed:
            print(json.dumps({
                "authoritative": False, "historicalAttestationValid": False,
                "error": f"decision digest mismatch: envelope claims {claimed}, content "
                         f"hashes to {actual}; the decision was modified after it was "
                         f"produced"}, indent=2))
            return VERIFY_BUNDLE_EXITS["VERIFICATION_FAILED"]
        decision = _rehydrate(body)
        if decision.digest() != actual:
            print(json.dumps({"authoritative": False, "historicalAttestationValid": False,
                              "error": "rehydrated decision does not reproduce the "
                                       "envelope digest"}, indent=2))
            return VERIFY_BUNDLE_EXITS["VERIFICATION_FAILED"]
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": f"unreadable bundle: {type(exc).__name__}: {exc}"}),
              file=sys.stderr)
        return VERIFY_BUNDLE_EXITS["INVALID_INPUT"]

    # 2. Skill/profile digest consistency: a decision claiming a shipped profile must carry
    #    that profile's real digest, or the bundle is claiming a bar nobody can check.
    problems = []
    profile = BUILTIN.get(decision.profile_id)
    if profile is not None and profile.digest() != decision.profile_digest:
        problems.append(f"profile digest mismatch: decision claims "
                        f"{decision.profile_digest[:16]}… for shipped profile "
                        f"{decision.profile_id!r}, which hashes to "
                        f"{profile.digest()[:16]}…")

    # 3. Artifact digest, when the bundle carries the artifact itself.
    artifact_checked = False
    artifact = args.artifact or (str(directory / "artifact")
                                 if (directory / "artifact").is_file() else None)
    if artifact and decision.subject.artifact_digest:
        import hashlib as _h
        alg = "sha512" if len(decision.subject.artifact_digest) == 128 else "sha256"
        hasher = _h.new(alg)
        try:
            with open(artifact, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    hasher.update(chunk)
            if hasher.hexdigest() != decision.subject.artifact_digest.lower():
                problems.append(
                    f"the bundled artifact hashes to {hasher.hexdigest()[:16]}… but the "
                    f"decision's subject.artifactDigest is "
                    f"{decision.subject.artifact_digest[:16]}…")
            else:
                artifact_checked = True
        except OSError as exc:
            problems.append(f"bundled artifact unreadable: {exc}")

    if problems:
        print(json.dumps({"authoritative": False, "historicalAttestationValid": False,
                          "semanticStatus": decision.semantic_status.value,
                          "problems": problems}, indent=2))
        return VERIFY_BUNDLE_EXITS["VERIFICATION_FAILED"]

    # 4. THE ENGINE. Same adapters, same rule table, same refusals.
    config_path = args.authority_config or (
        str(directory / "authority-config.json")
        if (directory / "authority-config.json").is_file() else None)
    attestation, prov = (None, ProvenanceStatus.NONE)
    if config_path:
        attestation, prov = _attest(decision, config_path)

    reason_codes = list(attestation.reason_codes) if attestation else []
    historical_valid = (decision.semantic_status is SemanticStatus.PASSED
                        and prov in (ProvenanceStatus.CI_ATTESTED,
                                     ProvenanceStatus.INDEPENDENTLY_ATTESTED))

    # 5. CURRENT EXTERNAL STATE. Authoritative means "true NOW", which a recording cannot
    #    say. A live recheck needs network, a token and the kit; absence is BLOCKED-not-
    #    assumed and the result honestly drops to historical.
    rechecked = False
    recheck_detail = "not attempted (no authority config or kit)"
    if attestation is not None and prov is ProvenanceStatus.INDEPENDENTLY_ATTESTED:
        recheck_detail, rechecked = _recheck_current_state(decision, config_path)

    authoritative = bool(historical_valid
                         and prov is ProvenanceStatus.INDEPENDENTLY_ATTESTED
                         and rechecked)
    result = {
        "schema": "shipgate.verify-bundle/1",
        "authoritative": authoritative,
        "semanticStatus": decision.semantic_status.value,
        "provenanceStatus": prov.value,
        "historicalAttestationValid": historical_valid,
        "currentExternalStateRechecked": rechecked,
        "currentExternalStateDetail": recheck_detail,
        "artifactDigestChecked": artifact_checked,
        # OFFICIAL SLSA BUILD LEVEL — deliberately separate from Ship Gate's own authority
        # tiers and deliberately UNVERIFIED in this release: this engine verifies GitHub
        # artifact attestations, but it does NOT verify the platform's official SLSA Build
        # L3 path (the hardened reusable-workflow pattern), and inferring L3 from Ship
        # Gate's own independent-verification outcome is exactly the substitution the v4.2
        # plan forbids.
        "slsaBuildLevel": "UNVERIFIED",
        "reasonCodes": reason_codes,
        "decisionDigest": actual,
    }
    if authoritative:
        result["humanVerdict"] = ("INDEPENDENTLY ATTESTED — historical evidence verified "
                                  "and current external state rechecked")
        code = VERIFY_BUNDLE_EXITS["AUTHORITATIVE"]
    elif historical_valid:
        result["humanVerdict"] = ("VALID HISTORICAL ATTESTATION — CURRENT EXTERNAL STATE "
                                  "NOT RECHECKED")
        code = VERIFY_BUNDLE_EXITS["VALID_NOT_AUTHORITATIVE"]
    elif decision.semantic_status is SemanticStatus.PASSED and config_path is None:
        result["humanVerdict"] = ("DECISION ENVELOPE INTACT — no authority evidence was "
                                  "supplied, so no provenance claim was checked or made")
        code = VERIFY_BUNDLE_EXITS["VALID_NOT_AUTHORITATIVE"]
    else:
        blocked = any(c in ("AUT_TOOL_MISSING", "AUT_KIT_ABSENT") for c in reason_codes)
        result["humanVerdict"] = ("EXTERNAL VERIFICATION BLOCKED — a required tool or "
                                  "capability is absent here" if blocked else
                                  "VERIFICATION FAILED — the evidence does not establish "
                                  "what it claims")
        code = (VERIFY_BUNDLE_EXITS["BLOCKED"] if blocked
                else VERIFY_BUNDLE_EXITS["VERIFICATION_FAILED"])
    print(json.dumps(result, indent=2))
    return code


def _recheck_current_state(decision, config_path):
    """(detail, ok). A LIVE look at the state the recorded evidence describes.

    Corroboration, not replacement: the award already stands on the signed recording; this
    answers only "is the protected environment still a protected boundary NOW". Network or
    token absence is reported as not-rechecked, never as a failure of the recording.
    """
    try:
        from shipgate.authority import live
        from shipgate.authority.contracts import AuthorityConfig
        from shipgate.authority.parsers import gh as gh_parser
        config = AuthorityConfig.from_path(config_path)
        name = config.gh.get("environmentName")
        if not name:
            return "no environment name in the config to recheck", False
        usable, why = live.available()
        if not usable:
            return f"live recheck impossible: {why}", False
        observation = live.observe_environment(decision.subject.repository, name,
                                               fetch=config.gh.get("_fetch"))
        env_res = gh_parser.parse_environment(
            json.dumps(observation["environment"]["body"]),
            gh_version=config.gh.get("version"))
        if not env_res.ok:
            return f"live recheck refused: {env_res.detail}", False
        qualifies, _code, detail = gh_parser.is_qualifying_environment(env_res.data)
        if not qualifies:
            return (f"the environment NO LONGER qualifies as a protected boundary: "
                    f"{detail}"), False
        return (f"live recheck at {observation['environment']['url']}: the environment "
                f"still qualifies"), True
    except Exception as exc:  # noqa: BLE001
        return f"live recheck could not run ({type(exc).__name__}: {exc})", False


def cmd_doctor(args):
    """Report what this environment can and cannot do. Never lies by omission."""
    import platform
    from shipgate.execadapter import containment as C
    from shipgate.version import SUPPORTED_PLATFORMS

    rec = C.detect()
    # `.lower()` on the MACHINE too: Windows reports "AMD64", so a case-sensitive
    # normalisation produced the tag "windows-AMD64" and would have produced
    # "linux-AMD64" on any host that spelled it that way — a supported platform
    # reported as unsupported.
    tag = (f"{platform.system().lower()}-{platform.machine().lower()}"
           .replace("amd64", "x86_64"))
    auth = authority_status()
    info = {
        "shipgate": SKILL_VERSION,
        "python": platform.python_version(),
        "platform": tag,
        "platformSupported": tag in SUPPORTED_PLATFORMS,
        "declaredSupportedPlatforms": list(SUPPORTED_PLATFORMS),
        "containment": {
            "kind": rec["kind"],
            "established": rec["established"],
            "description": C.describe(rec),
            "candidates": rec["candidates"],
            "hardeningOnly": rec["hardening"],
        },
        "authorityKit": auth,
    }
    from shipgate.collectors import ALL_COLLECTORS, describe_plan
    from shipgate.collectors.adversarial import admission, describe as describe_adversarial
    info["collectorPlan"] = describe_plan([c() for c in ALL_COLLECTORS],
                                          parallelism=8).splitlines()
    # Every phase collector's fail-first admission runs against in-memory references, so it
    # needs no target, no network and no configuration — which means `doctor` can tell you
    # whether each instrument works BEFORE you point it at anything. All four are reported
    # together: an operator who reads one and assumes the rest is exactly the reader this
    # section exists to stop.
    adm = admission()
    info["adversarialProbe"] = {
        "admitted": adm["admitted"],
        "seededDefectsCaught": adm["seededFindingCount"],
        "falseAlarmsOnCorrectApp": len(adm["falseAlarmsOnCorrectApp"]),
        "detail": adm["detail"],
        "describes": describe_adversarial().splitlines(),
    }
    info["phaseCheckers"] = _phase_checker_admissions()
    if getattr(args, "live", False):
        info["liveObservation"] = _live_field_check(args)
    if auth["present"]:
        try:
            import shipgate.authority as A
            info["authorityKit"] = A.availability()
        except Exception as exc:  # noqa: BLE001
            info["authorityKit"] = {"present": True, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(info, indent=2))
    if not info["platformSupported"]:
        return 1
    return 0 if rec["established"] else 3


def cmd_selftest(args):
    """Run the shipped test suite. No skips are permitted to count as a pass.

    REFUSES AN UNSUPPORTED PLATFORM before running anything. This release declares
    `linux-x86_64` only, and `doctor` has always refused elsewhere — but `selftest` did not,
    so running it on Windows produced 18 failures and 5 errors across symlink, permission-bit,
    process-control and shell tests. Every one of them was the suite correctly observing that
    it was on the wrong operating system, and collectively they said it in the least usable
    way available: 23 scattered assertion errors instead of one sentence. A gate whose whole
    doctrine is "fail closed, visibly, with a reason" does not get to answer this question
    with a stack trace. `--force` runs anyway, for someone deliberately probing portability.
    """
    import platform
    import unittest
    from shipgate.version import SUPPORTED_PLATFORMS
    # `.lower()` on the MACHINE too: Windows reports "AMD64", so a case-sensitive
    # normalisation produced the tag "windows-AMD64" and would have produced
    # "linux-AMD64" on any host that spelled it that way — a supported platform
    # reported as unsupported.
    tag = (f"{platform.system().lower()}-{platform.machine().lower()}"
           .replace("amd64", "x86_64"))
    if tag not in SUPPORTED_PLATFORMS and not getattr(args, "force", False):
        print(f"gate.py selftest: REFUSING to run on {tag}. This release supports "
              f"{', '.join(sorted(SUPPORTED_PLATFORMS))} only (OPS_PLATFORM_UNSUPPORTED).\n"
              f"Parts of the suite assert POSIX semantics — symlinks, permission bits, "
              f"process-group termination, shell behaviour — so the failures you would get "
              f"here describe the host, not the release. Run it in a Linux x86_64 container, "
              f"or pass --force to run anyway and read the result as portability data rather "
              f"than as a pass or a fail.", file=sys.stderr)
        return 1
    root = Path(__file__).resolve().parent.parent / "tests"
    if not root.is_dir():
        _fail(f"test tree not found at {root}")
    loader = unittest.TestLoader()
    suite = loader.discover(str(root), top_level_dir=str(root.parent))
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    skipped = len(result.skipped)
    if skipped:
        print(f"\nREFUSING: {skipped} test(s) were skipped. A skipped required test is not a "
              f"pass. Skips: {[str(t[0]) for t in result.skipped]}", file=sys.stderr)
    ok = result.wasSuccessful() and not skipped and not loader.errors
    print(f"\ntests={result.testsRun} failures={len(result.failures)} "
          f"errors={len(result.errors)} skipped={skipped} -> {'OK' if ok else 'NOT OK'}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------

def _attest(decision, config_path):
    """Consult the OPTIONAL authority kit. Never alters the decision.

    Any failure — kit absent, import error, adapter refusal — resolves to UNAVAILABLE. An
    adapter that raises cannot take the run down with it, and cannot produce an attestation
    by accident.
    """
    status = authority_status()
    if not status["present"]:
        print("authority: kit is not installed (AUT_KIT_ABSENT). The VERIFIED semantic "
              "result stands on its own.", file=sys.stderr)
        return None, ProvenanceStatus.UNAVAILABLE
    try:
        import shipgate.authority as A
        attestation = A.attest(decision, config_path)
    except Exception as exc:  # noqa: BLE001
        print(f"authority: adapter failed ({type(exc).__name__}: {exc}); reporting "
              "AUTHORITY_UNAVAILABLE.", file=sys.stderr)
        return None, ProvenanceStatus.UNAVAILABLE
    if attestation is None:
        return None, ProvenanceStatus.UNAVAILABLE
    prov = attestation.provenance_status
    if prov in (ProvenanceStatus.CI_ATTESTED, ProvenanceStatus.INDEPENDENTLY_ATTESTED):
        # Belt and braces: AttestedDecision enforces this too, but refusing here means a
        # buggy adapter cannot even get as far as constructing one.
        from shipgate.models.decision import AttestedDecision
        AttestedDecision(decision=decision, attestation=attestation)
        return attestation, prov
    return attestation, ProvenanceStatus.UNAVAILABLE


def _persist_attestation(workdir, decision, attestation, requested):
    """Write what happened on the provenance axis, beside the decision.

    FIX-ATTESTATION-NOT-PERSISTED: an `--authority` run printed AUTHORITY_UNAVAILABLE and
    exited 3, but the durable `decision.json` recorded provenanceStatus NONE — correct, since
    authority may never alter a decision, yet it meant an auditor reading the artifact later
    could not tell a refused attestation from a run that never asked. The refusal now lives in
    its own file, leaving the decision untouched.
    """
    if not requested:
        return
    path = Path(workdir) / "attestation.json"
    body = {
        "schema": "shipgate.attestation-record/1",
        "decisionDigest": decision.digest(),
        "authorityRequested": True,
        "provenanceStatus": (attestation.provenance_status.value if attestation
                             else ProvenanceStatus.UNAVAILABLE.value),
        "attestation": attestation.to_json() if attestation else None,
        "note": ("The decision is unchanged by this record. Authority may consume an immutable "
                 "decision; it may never alter, repair, replace, downgrade or bypass one."),
    }
    path.write_bytes(canonical_bytes(body))
    return path


def _emit(decision, attestation, args, workdir):
    if args.json:
        payload = decision.to_envelope()
        if attestation is not None:
            payload["attestation"] = attestation.to_json()
        sys.stdout.write(canonical_bytes(payload).decode("utf-8") + "\n")
    else:
        print(render_text(decision, attestation))
    if args.html:
        Path(args.html).write_text(render_html(decision, attestation), encoding="utf-8")
        print(f"\nHTML report: {args.html}", file=sys.stderr)
    print(f"artifacts: {workdir}", file=sys.stderr)


def _policy(args):
    base = Policy.from_env()
    mode = Mode(args.mode) if args.mode else base.mode
    containment = base.containment
    if args.allow_host_exec:
        containment = type(containment)(
            required=containment.required, accepted=containment.accepted,
            allow_host_exec=True,
            default_timeout_seconds=args.timeout or containment.default_timeout_seconds,
            max_output_bytes=containment.max_output_bytes)
    elif args.timeout:
        containment = type(containment)(
            required=containment.required, accepted=containment.accepted,
            allow_host_exec=containment.allow_host_exec,
            default_timeout_seconds=args.timeout,
            max_output_bytes=containment.max_output_bytes)
    cache = base.cache
    if getattr(args, "cache", False) or getattr(args, "cache_dir", None):
        cache = type(cache)(enabled=True,
                            directory=args.cache_dir or cache.directory,
                            max_age_seconds=cache.max_age_seconds)
    parallelism = max(1, int(getattr(args, "parallelism", None) or base.parallelism))
    return type(base)(
        mode=mode, containment=containment, cache=cache,
        break_glass=base.break_glass, authority_requested=bool(args.authority),
        authority_config_path=args.authority_config, parallelism=parallelism)


def _signals(names):
    for n in names or ():
        try:
            yield EscalationSignal(n.upper())
        except ValueError:
            _fail(f"unknown escalation signal {n!r}; known: "
                  f"{[s.value for s in EscalationSignal]}")


def _required_coverage(text):
    """Parse `--require-coverage`, refusing any phase no collector can establish.

    The refusal is the feature, and it is a rule rather than a list. A phase may only be
    required if something OBSERVES it; requiring one that nothing observes could be satisfied
    only by the agent SAYING it ran, which would make a self-report load-bearing and hand
    anyone who wants a green run a one-line way to get it.

    In v4.0 all four agentic phases happen to have a collector, so nothing is currently
    refused on those grounds. The check stays because the rule is not "these four are fine" —
    it is "only a collector-backed phase may be required", and the day a fifth agentic phase
    is tracked without a collector, this refuses it rather than silently obliging.
    """
    if not text:
        return ()
    from shipgate.models.coverage import (
        AGENTIC_PHASES, COLLECTOR_BACKED_PHASES, PHASE_TITLES)
    wanted, unknown, uncollectable = [], [], []
    for part in str(text).replace(";", ",").split(","):
        name = part.strip().upper()
        if not name:
            continue
        if name in COLLECTOR_BACKED_PHASES:
            if name not in wanted:
                wanted.append(name)
        elif name in AGENTIC_PHASES:
            uncollectable.append(name)
        else:
            unknown.append(name)
    if unknown:
        _fail(f"--require-coverage: unknown phase(s) {', '.join(unknown)}; the tracked "
              f"phases are {', '.join(AGENTIC_PHASES)}")
    if uncollectable:
        _fail(
            f"--require-coverage: {', '.join(uncollectable)} cannot be required. "
            f"No collector observes "
            + "; ".join(f"{p} ({PHASE_TITLES.get(p, '')[:60]})" for p in uncollectable)
            + f", so requiring it could only be satisfied by the operating agent SAYING it "
              f"ran — a self-report, which this gate never lets decide anything. Phases with "
              f"a collector: {', '.join(COLLECTOR_BACKED_PHASES)}.")
    return tuple(wanted)


def _phase_claims(args):
    """The self-attested phase record from the command line, or None to read the file.

    `None` and `{}` are different and the difference matters. `None` means "nobody said
    anything here, look for phases.json"; `{}` means "the caller spoke, and named no
    phases", which is a claim that none ran. Collapsing the two would make `--phases ''`
    silently fall back to a file the operator may not have known about.
    """
    from shipgate.models.coverage import parse_phase_list
    if args.phases_file:
        try:
            doc = loads_strict(Path(args.phases_file).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            _fail(f"cannot read --phases-file {args.phases_file}: {type(exc).__name__}: {exc}")
        if isinstance(doc, dict) and isinstance(doc.get("phases"), dict):
            doc = doc["phases"]
        if not isinstance(doc, dict):
            _fail("--phases-file must contain a JSON object, or an object with a 'phases' "
                  "object inside it")
        claims = dict(doc)
    else:
        claims = {}
    if args.phases is not None:
        claims.update(parse_phase_list(args.phases))
    elif not args.phases_file:
        return None
    return claims


def _options(pairs, options_file=None):
    """Collector options.

    `--option NAME=VALUE` handles scalars. Options whose value is a list or an object (route
    lists, declared CUJs, fail-first candidates) cannot be expressed on a command line
    without inventing an encoding, so `--options-file` takes a JSON object instead. Explicit
    `--option` flags win over the file, so a one-off override does not require editing it.
    """
    out = {}
    if options_file:
        try:
            doc = loads_strict(Path(options_file).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            _fail(f"cannot read --options-file {options_file}: {type(exc).__name__}: {exc}")
        if not isinstance(doc, dict):
            _fail(f"--options-file must contain a JSON object, got {type(doc).__name__}")
        out.update(doc)
    for pair in pairs or ():
        if "=" not in pair:
            _fail(f"--option expects name=value, got {pair!r}")
        k, v = pair.split("=", 1)
        out[k.strip()] = _coerce(v.strip())
    return out


def _coerce(v):
    low = v.lower()
    if low in ("true", "yes", "1"):
        return True
    if low in ("false", "no", "0"):
        return False
    try:
        return int(v)
    except ValueError:
        return v


def _rehydrate(body):
    """Rebuild a Decision from its JSON. Used by `report`, which must not re-run anything."""
    from shipgate.models.decision import (
        CheckResult, CujOutcome, Decision, HeldOutOutcome, SubjectIdentity, ThresholdResult)
    from shipgate.models.finding import Finding, FindingState, Severity

    s = body["subject"]
    findings = []
    for f in body.get("findings") or []:
        try:
            findings.append(Finding(
                id=f["id"], severity=Severity(f["severity"]), state=FindingState(f["state"]),
                title=f.get("title", ""), detail=f.get("detail", ""),
                source=f.get("source", ""), reason_code=f.get("reasonCode"),
                location=f.get("location"), evidence_refs=tuple(f.get("evidenceRefs") or []),
                reason=f.get("reason"), authority=f.get("authority"),
                recorded_at=f.get("recordedAt", ""), cuj=bool(f.get("cuj"))))
        except ValueError:
            continue
    return Decision(
        decision_id=body["decisionId"], created_at=body["createdAt"],
        subject=SubjectIdentity(
            repository=s["repository"], commit=s["commit"], tree_digest=s["treeDigest"],
            artifact_id=s.get("artifactId"), artifact_digest=s.get("artifactDigest"),
            branch=s.get("branch")),
        profile_id=body["profile"]["id"], profile_digest=body["profile"]["digest"],
        semantic_status=SemanticStatus(body["semanticStatus"]),
        reason_codes=tuple(body.get("reasonCodes") or ()),
        checks=tuple(CheckResult(
            check_id=c["checkId"], title=c["title"], passed=c["passed"],
            required=c["required"], showstopper=c["showstopper"],
            evidence_kind=c["evidenceKind"], reason_code=c.get("reasonCode"),
            detail=c.get("detail", "")) for c in body.get("checks") or ()),
        thresholds=tuple(ThresholdResult(
            threshold_id=t["thresholdId"], metric=t["metric"], comparison=t["comparison"],
            required_value=t["requiredValue"], measured_value=t.get("measuredValue"),
            passed=t["passed"], required=t["required"], unit=t.get("unit", ""),
            reason_code=t.get("reasonCode")) for t in body.get("thresholds") or ()),
        cujs=tuple(CujOutcome(
            id=c["id"], title=c.get("title", ""), status=c["status"],
            evidence_ref=c.get("evidenceRef"), detail=c.get("detail", ""))
            for c in body.get("cujs") or ()),
        heldout=tuple(HeldOutOutcome(
            suite_id=h["suiteId"], bound=h["bound"], evaluated=h["evaluated"],
            total=h["total"], passed=h["passed"], failed=h["failed"], errored=h["errored"],
            binding_digest=h.get("bindingDigest"), detail=h.get("detail", ""))
            for h in body.get("heldOut") or ()),
        findings=tuple(findings),
        required_evidence=tuple(body.get("requiredEvidence") or ()),
        received_evidence=tuple(body.get("receivedEvidence") or ()),
        input_digests=tuple(body.get("inputDigests") or ()),
        containment=body.get("containment") or {},
        # The coverage block must survive the round trip, or `gate.py report` would render a
        # clean-looking HTML report from a decision that carries a caveat — the caveat would
        # exist in the JSON and vanish in the artifact a human actually reads. Rebuilt through
        # `build_coverage` so the same construction rules apply: an on-disk `corroborated: true`
        # is NOT trusted from the file, it is re-derived from the file's own corroborated list,
        # which is the field the engine wrote.
        coverage=_rehydrate_coverage(body.get("coverage")),
        break_glass=body.get("breakGlass"), mode=body.get("mode", "enforce"),
        engine=body.get("engine", ""), schema=body.get("schema", ""),
        residual_risk=body.get("residualRisk", ""))


def _rehydrate_coverage(doc):
    """Rebuild a `PhaseCoverage` from the decision's JSON. Returns None when absent."""
    if not isinstance(doc, dict):
        return None
    from shipgate.models.coverage import build as build_coverage
    phases = doc.get("phases")
    claims = {}
    if isinstance(phases, list):
        for p in phases:
            if isinstance(p, dict) and p.get("phase"):
                claims[p["phase"]] = {"claim": p.get("claim"), "detail": p.get("detail", "")}
    corroborated = doc.get("corroborated")
    return build_coverage(
        claims,
        source=doc.get("source") or "operating_agent",
        note=doc.get("note") or "",
        corroborated=corroborated if isinstance(corroborated, list) else ())


def _fail(message, code=USAGE_ERROR):
    print(f"gate.py: {message}", file=sys.stderr)
    raise SystemExit(code)


# ---------------------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="gate.py",
        description=f"ship-gate {SKILL_VERSION} — semantic release gate. "
                    "Answers two independent questions: does the run pass on its merits "
                    "(Axis B), and is the evidence externally attested (Axis A).")
    p.add_argument("--version", action="version", version=f"ship-gate {SKILL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="collect evidence and produce a decision")
    r.add_argument("repo", help="path to the repository under evaluation")
    r.add_argument("--run-area", help="isolated run area (default: the repo itself)")
    r.add_argument("--profile", default="standard", choices=sorted(BUILTIN))
    r.add_argument("--mode", choices=[m.value for m in Mode],
                   help="advisory | observe | enforce (default: enforce). Mode changes only "
                        "whether this process BLOCKS: advisory and observe always exit 0. The "
                        "decision recorded on disk is identical in all three modes.")
    r.add_argument("--round", type=int, default=1)
    r.add_argument("--run-id")
    r.add_argument("--artifact", help="path to the built artifact being released")
    r.add_argument("--residual-risk", help="mandatory for a complete report")
    r.add_argument("--escalate", action="append", metavar="SIGNAL",
                   help="DECLARED_RISK | PROTECTED_AREA_CHANGED | UNRESOLVED_UNCERTAINTY | POLICY")
    r.add_argument("--recommend-profile", action="append", metavar="ID",
                   help="advisory recommendation; can raise the bar, never lower it")
    r.add_argument("--option", action="append", metavar="NAME=VALUE",
                   help="scalar collector option (bool/int/str)")
    r.add_argument("--options-file", metavar="PATH",
                   help="JSON object of collector options; the only way to pass list/object "
                        "values such as declared CUJs or route lists")
    r.add_argument("--timeout", type=int, help="default per-process timeout in seconds")
    r.add_argument("--parallelism", type=int, metavar="N",
                   help="run independent READ-ONLY collectors concurrently (default 1). "
                        "Tree-mutating and live-system collectors are always serial, and the "
                        "decision is identical at any value — see `doctor` for the plan.")
    r.add_argument("--cache", action="store_true",
                   help="reuse collector evidence for byte-identical inputs (same commit, "
                        "tree, artifact, options and collector version)")
    r.add_argument("--cache-dir", metavar="PATH",
                   help="where to keep cached evidence (default: <run-area>/shipgate-workdir/cache)")
    r.add_argument("--allow-env", action="append", metavar="NAME",
                   help="forward one named environment variable into the containment boundary "
                        "(e.g. NODE_EXTRA_CA_CERTS, HTTPS_PROXY behind a corporate proxy). "
                        "Secret-shaped names are refused regardless.")
    r.add_argument("--allow-host-exec", action="store_true",
                   help="explicitly accept running target code with NO containment boundary; "
                        "recorded in the decision and FAILS the containment check")
    r.add_argument("--phases", metavar="LIST",
                   help="comma-separated agentic phases you RAN, e.g. 'A2,G2,G3,H'. "
                        "SELF-ATTESTED: recorded, reported, and never able to raise the "
                        "outcome. Anything you do not name is recorded as NOT RUN.")
    r.add_argument("--phases-file", metavar="PATH",
                   help="JSON phase record; default <workdir>/phases.json when present. "
                        "See assets/templates/phases.json.")
    r.add_argument("--require-coverage", metavar="PHASES",
                   help="comma-separated phases that MUST be corroborated by a collector, "
                        "e.g. 'H'. Exits non-zero when a named phase is not COLLECTED. Only "
                        "phases with a real collector may be named — A2, G2 and G3 are "
                        "refused, because requiring them would mean blocking a release on a "
                        "self-report, which no flag is allowed to make load-bearing.")
    r.add_argument("--static-only", action="store_true",
                   help="run only read-only collectors (no target code executes)")
    r.add_argument("--authority", action="store_true",
                   help="consult the optional authority kit for provenance")
    r.add_argument("--authority-config", help="path to the authority configuration JSON")
    r.add_argument("--json", action="store_true", help="emit the canonical decision envelope")
    r.add_argument("--html", metavar="PATH", help="also write a self-contained HTML report")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verdict", help="re-derive the outcome from a decision on disk")
    v.add_argument("decision", help="path to decision.json")
    v.add_argument("--authority-config", metavar="PATH",
                   help="RE-VERIFY provenance against the raw evidence. Without this, a "
                        "provenance record beside the decision is reported and IGNORED: a "
                        "status in a file is a claim, not evidence.")
    v.set_defaults(func=cmd_verdict)

    at = sub.add_parser("attest",
                        help="attest an EXISTING decision without re-running the gate")
    at.add_argument("decision", help="path to decision.json")
    at.add_argument("--authority-config", required=True,
                    help="path to the authority configuration JSON")
    at.add_argument("--out", metavar="PATH",
                    help="where to write the attestation record "
                         "(default: attestation.json beside the decision)")
    at.set_defaults(func=cmd_attest)

    rep = sub.add_parser("report", help="render an HTML report from a decision on disk")
    rep.add_argument("decision")
    rep.add_argument("--out", default="SHIP-GATE-REPORT.html")
    rep.set_defaults(func=cmd_report)

    pr = sub.add_parser("profiles", help="list or show the shipped semantic profiles")
    pr.add_argument("--show", metavar="ID")
    pr.set_defaults(func=cmd_profiles)

    ob = sub.add_parser("observe", help="phase 1: observe GitHub and record what was seen")
    ob.add_argument("decision", help="the published decision.json this observation is about")
    ob.add_argument("--repo", required=True, help="owner/repo to observe")
    ob.add_argument("--environment", required=True, help="deployment environment name")
    ob.add_argument("--out", required=True, help="where to write the observation JSON")
    ob.add_argument("--run-id", default="", help="the CI run this observation belongs to")
    ob.add_argument("--run-attempt", default="",
                    help="the attempt within that run; a rerun is a different execution")
    ob.add_argument("--external-time", type=int, default=None,
                    help="a verified external timestamp (e.g. from a Rekor checkpoint)")
    ob.set_defaults(func=cmd_observe)

    vb = sub.add_parser("verify-bundle",
                        help="verify a persisted evidence bundle with the same engine "
                             "that produced it")
    vb.add_argument("directory", help="the evidence directory (decision.json plus the "
                                      "authority evidence it names)")
    vb.add_argument("--authority-config", default=None,
                    help="override the bundle's authority-config.json")
    vb.add_argument("--artifact", default=None,
                    help="override the bundled artifact path for the digest re-hash")
    vb.set_defaults(func=cmd_verify_bundle)

    d = sub.add_parser("doctor", help="report what this environment can and cannot do")
    d.add_argument("--live", action="store_true",
                   help="additionally make ONE real GitHub observation and report exactly "
                        "what came back. Off by default: doctor must stay usable offline, "
                        "and a diagnostic that silently dials out is a surprise.")
    d.add_argument("--live-repo", default="",
                   help="owner/repo to observe with --live (default: the SHIPGATE_LIVE_REPO "
                        "environment variable)")
    d.add_argument("--live-environment", default="",
                   help="deployment environment name to observe with --live (default: the "
                        "SHIPGATE_LIVE_ENVIRONMENT environment variable)")
    d.set_defaults(func=cmd_doctor)

    st = sub.add_parser("selftest", help="run the shipped test suite")
    st.add_argument("--verbose", action="store_true")
    st.add_argument("--force", action="store_true",
                    help="run the suite on an unsupported platform anyway; the "
                         "result is portability data, not a pass or a fail")
    st.set_defaults(func=cmd_selftest)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return USAGE_ERROR
    except BrokenPipeError:
        # FIX-CLI-BROKEN-PIPE. `gate.py profiles | head` closes the pipe early. That is the reader's decision, not
        # an error in the gate, and printing "internal error: BrokenPipeError" at somebody who
        # piped into `head` is exactly the kind of noise that teaches people to ignore this
        # tool's output. Redirect the dangling stdout to /dev/null so the interpreter's own
        # shutdown flush cannot raise a second time, and exit quietly.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"gate.py: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.environ.get("SHIPGATE_DEBUG"):
            import traceback
            traceback.print_exc()
        return USAGE_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
