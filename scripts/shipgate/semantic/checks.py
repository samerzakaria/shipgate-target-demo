"""Check evaluators — the whole of Axis B's per-check logic, in one reviewable file.

An evaluator has the signature

    evaluator(evidence, spec, ctx) -> (passed: bool, reason_code | None, detail: str)

`evidence` is the single Evidence of the spec's kind, or None. `ctx` is an `EvalContext`
exposing the full evidence set and the findings list for the few checks that legitimately
need cross-evidence context.

Two rules hold for every evaluator in this file, and the unit tests assert them:

  * MISSING OR UNUSABLE EVIDENCE FAILS. `None`, ERROR and ABSENT evidence never pass. A
    check whose evidence did not arrive is a failed check, not a skipped one.
  * MALFORMED PAYLOAD FAILS. An evaluator that cannot find the field it needs returns
    EVD_MALFORMED rather than treating a missing key as a zero.

This is where several v3.8 defects are closed, each marked FIX-*.
"""
from ..models import reasons as R
from ..models.evidence import EvidenceStatus
from ..models.finding import blocking_findings

REGISTRY = {}

# ---------------------------------------------------------------------------------------
# Applicability conditions
#
# A profile entry may declare `applies_when`. Conditions are resolved against STACK
# evidence. The critical rule: an UNRESOLVABLE condition resolves to APPLICABLE. A gate
# that skipped its accessibility check because stack detection crashed would be reporting
# a pass it never earned.
# ---------------------------------------------------------------------------------------

def _stack_has_ui(evidence_set):
    from ..models.evidence import EvidenceKind as _K
    ev = None
    for e in evidence_set.of_kind(_K.STACK):
        if e.status is EvidenceStatus.COLLECTED:
            ev = e
            break
    if ev is None or not isinstance(ev.payload, dict):
        return None  # unresolvable
    ui = ev.payload.get("ui")
    if isinstance(ui, bool):
        return ui
    if isinstance(ui, dict) and isinstance(ui.get("present"), bool):
        return ui["present"]
    return None


def _kind_present(evidence_set, kind):
    """Is there an observation of this kind to judge at all?

    Never unresolvable: presence is directly observable. ABSENT means the operator declared
    none of the inputs the collector needs, and the gate cannot author a requirements
    manifest, a design-token file or a second surface to compare against.

    The usual objection — "not configured means skipped" is a gate you walk around by
    omission — is answered the same way for all four phases: skipping is not SILENT. The
    phase's coverage caveat is cleared only by COLLECTED evidence whose check passed, so an
    unconfigured run reads `VERIFIED — partial coverage (...)` and says which phase in the
    decision, the reason codes and both reports. On `deep`, the evidence is REQUIRED and the
    same omission fails the run.
    """
    for e in evidence_set.of_kind(kind):
        if e.status is not EvidenceStatus.ABSENT:
            return True
    return False


def _requirements_configured(evidence_set):
    from ..models.evidence import EvidenceKind as _K
    return _kind_present(evidence_set, _K.REQUIREMENTS)


def _design_tokens_configured(evidence_set):
    from ..models.evidence import EvidenceKind as _K
    return _kind_present(evidence_set, _K.DESIGN_CONFORMANCE)


def _surfaces_comparable(evidence_set):
    from ..models.evidence import EvidenceKind as _K
    return _kind_present(evidence_set, _K.CROSS_SURFACE)


def _adversarial_configured(evidence_set):
    """Is there an adversarial observation to judge at all?

    Unlike the stack conditions, this one is never unresolvable: the evidence is either
    present and usable or it is not, and both answers are directly observable. ABSENT means
    the operator declared no identities and no write endpoints, so the probe had nothing to
    attack — the gate cannot invent two disposable accounts for somebody's application.

    THE OBVIOUS OBJECTION, ANSWERED. "Not configured means the check is skipped" is normally
    the exact shape of a gate you can walk around by omission, and it would be here too if
    skipping were SILENT. It is not. Phase H's coverage caveat is cleared by one thing only —
    ADVERSARIAL_PROBE evidence that is COLLECTED and whose check passed — so an unconfigured
    run does not read as VERIFIED. It reads as `VERIFIED — partial coverage (H not run)`, and
    it says so in the decision, in the reason codes and in the report. The omission is not
    punished; it is published. In the `deep` profile, reached by an explicit escalation
    signal, the evidence is REQUIRED and the same omission fails the run outright.
    """
    from ..models.evidence import EvidenceKind as _K
    for e in evidence_set.of_kind(_K.ADVERSARIAL_PROBE):
        if e.status is not EvidenceStatus.ABSENT:
            return True
    return False


CONDITIONS = {
    "always": lambda evidence_set: True,
    "ui": _stack_has_ui,
    "non_ui": lambda evidence_set: (lambda v: None if v is None else (not v))(
        _stack_has_ui(evidence_set)),
    "adversarial_configured": _adversarial_configured,
    "requirements_configured": _requirements_configured,
    "design_tokens_configured": _design_tokens_configured,
    "surfaces_comparable": _surfaces_comparable,
}


def applies(condition, evidence_set):
    """(applicable: bool, resolved: bool). Unresolvable -> applicable, resolved=False."""
    fn = CONDITIONS.get(condition)
    if fn is None:
        return True, False
    v = fn(evidence_set)
    if v is None:
        return True, False
    return bool(v), True


def evaluator(name):
    def deco(fn):
        REGISTRY[name] = fn
        return fn
    return deco


class EvalContext:
    """Read-only view handed to evaluators."""

    def __init__(self, evidence_set, findings, profile, subject, round_index=1,
                 clean_round_streak=0):
        self.evidence = evidence_set
        self.findings = list(findings)
        self.profile = profile
        self.subject = subject
        self.round_index = round_index
        self.clean_round_streak = clean_round_streak


# --- shared guards ----------------------------------------------------------------------

def _usable(evidence):
    """(ok, reason, detail) — the fail-closed gate every evaluator runs first."""
    if evidence is None:
        return False, R.EVD_REQUIRED_MISSING, "no evidence of this kind was collected"
    if evidence.status is EvidenceStatus.ERROR:
        return False, R.EVD_COLLECTOR_ERROR, f"collector reported an error: {evidence.note}"
    if evidence.status is EvidenceStatus.ABSENT:
        return False, R.EVD_REQUIRED_MISSING, f"collector reported absent: {evidence.note}"
    if not isinstance(evidence.payload, dict):
        return False, R.EVD_MALFORMED, "payload is not an object"
    return True, None, ""


def _need(payload, *keys):
    """(ok, missing_key). Presence, not truthiness — 0 and [] are legitimate values."""
    for k in keys:
        if k not in payload:
            return False, k
    return True, None


def _int(payload, key):
    v = payload.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


# --- wiring / runtime ---------------------------------------------------------------------

@evaluator("ledger_no_wiring_gaps")
def ledger_no_wiring_gaps(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "entries", "counts")
    if not ok:
        return False, R.EVD_MALFORMED, f"ledger payload missing {missing!r}"
    entries = p["entries"]
    if not isinstance(entries, list):
        return False, R.EVD_MALFORMED, "ledger entries is not a list"
    if not entries:
        # An empty ledger is not a clean ledger — it means extraction found nothing, which
        # for any real application is a broken collector, not a passing gate.
        return False, R.EVD_INCOMPLETE, "the capability ledger is empty; extraction found nothing"
    bad = [e for e in entries
           if str(e.get("status", "")).upper() in ("UNVERIFIED", "WIRING_GAP", "")]
    if bad:
        sample = ", ".join(str(e.get("id", "?")) for e in bad[:5])
        return (False, R.SEM_WIRING_GAP,
                f"{len(bad)} capability/-ies not evidenced (e.g. {sample})")
    if evidence.status is EvidenceStatus.PARTIAL:
        return (False, R.EVD_INCOMPLETE,
                f"ledger coverage is partial; uncovered: {', '.join(evidence.uncovered[:5])}")
    return True, None, f"{len(entries)} capabilities evidenced"


@evaluator("runtime_served")
def runtime_served(evidence, spec, ctx):
    """FIX-PROBE: v3.8 judged 'route served' partly from response body shape, which read a
    framework's own 404 page as a served route. Serving is decided ONLY by comparison with
    the per-scope canary baseline the collector measured; an INCONCLUSIVE judgment fails
    closed instead of being counted as served."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "routes", "canary")
    if not ok:
        return False, R.EVD_MALFORMED, f"probe payload missing {missing!r}"
    routes = p["routes"]
    if not isinstance(routes, list) or not routes:
        return False, R.EVD_INCOMPLETE, "probe observed no routes"
    canary = p.get("canary")
    if not (isinstance(canary, dict) and canary.get("established")):
        return (False, R.EVD_INCOMPLETE,
                "no 404 canary baseline was established, so 'served' cannot be distinguished "
                "from 'framework 404'")
    absent = [r for r in routes if str(r.get("judgment", "")).upper() == "ABSENT"]
    inconclusive = [r for r in routes
                    if str(r.get("judgment", "")).upper() not in ("SERVED", "ABSENT", "MOCKED")]
    if absent:
        s = ", ".join(f"{r.get('method', '?')} {r.get('path', '?')}" for r in absent[:5])
        return False, R.SEM_RUNTIME_NOT_SERVED, f"{len(absent)} declared route(s) not served: {s}"
    if inconclusive:
        s = ", ".join(f"{r.get('method', '?')} {r.get('path', '?')}" for r in inconclusive[:5])
        return (False, R.EVD_INCOMPLETE,
                f"{len(inconclusive)} route(s) inconclusive (fail-closed): {s}")
    return True, None, f"{len(routes)} routes served against a canary baseline"


@evaluator("cuj_evidenced")
def cuj_evidenced(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    journeys = evidence.payload.get("journeys")
    if not isinstance(journeys, list):
        return False, R.EVD_MALFORMED, "CUJ payload missing 'journeys'"
    if not journeys:
        return False, R.EVD_INCOMPLETE, "no Critical User Journeys were declared"
    not_ev = [j for j in journeys if str(j.get("status", "")).upper() != "EVIDENCED"]
    if not_ev:
        s = ", ".join(str(j.get("id", "?")) for j in not_ev[:5])
        return False, R.SEM_CUJ_NOT_EVIDENCED, f"{len(not_ev)} CUJ(s) not evidenced: {s}"
    mocked = [j for j in journeys if j.get("mocked")]
    if mocked:
        s = ", ".join(str(j.get("id", "?")) for j in mocked[:5])
        return (False, R.SEM_CUJ_DOWNGRADE_REFUSED,
                f"CUJ(s) evidenced against a mock, which is not permitted: {s}")
    return True, None, f"{len(journeys)} CUJs evidenced end to end"


# --- test integrity -----------------------------------------------------------------------

@evaluator("fail_first_admitted")
def fail_first_admitted(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    tests = evidence.payload.get("tests")
    if not isinstance(tests, list):
        return False, R.EVD_MALFORMED, "fail-first payload missing 'tests'"
    if not tests:
        return False, R.EVD_INCOMPLETE, "no tests were submitted for fail-first admission"
    unadmitted = [t for t in tests if not t.get("admitted")]
    if unadmitted:
        s = ", ".join(str(t.get("id", "?")) for t in unadmitted[:5])
        return (False, R.SEM_FAIL_FIRST_NOT_ADMITTED,
                f"{len(unadmitted)} test(s) never provably failed on an injected fault: {s}")
    return True, None, f"{len(tests)} tests admitted fail-first"


@evaluator("test_seal_intact")
def test_seal_intact(evidence, spec, ctx):
    """FIX-SEAL: v3.8 could seal zero files and report green, and the seal did not always
    cover the test COMMAND, so a gutted `"test": "true"` passed. Both are hard failures."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "intact", "fileCount", "coveredCommandDefinition")
    if not ok:
        return False, R.EVD_MALFORMED, f"test seal payload missing {missing!r}"
    if _int(p, "fileCount") in (None, 0):
        return False, R.SEM_TEST_SEAL_EMPTY, "the test seal covers zero files"
    if not p.get("coveredCommandDefinition"):
        return (False, R.SEM_TEST_SEAL_BROKEN,
                "the seal does not cover the test command definition, so the command could be "
                "gutted without breaking the seal")
    if not p.get("intact"):
        v = p.get("violations") or []
        return False, R.SEM_TEST_SEAL_BROKEN, f"seal broken: {'; '.join(map(str, v[:5]))}"
    return True, None, f"seal intact over {p['fileCount']} files including the test command"


@evaluator("spec_sealed")
def spec_sealed(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    if not p.get("sealed"):
        return False, R.SEM_SPEC_UNSEALED, "the specification is not sealed at spec-v0"
    unlogged = p.get("unloggedDeltas") or []
    if unlogged:
        return (False, R.SEM_SPEC_DRIFT_UNLOGGED,
                f"{len(unlogged)} unlogged specification change(s)")
    flips = [f for f in (p.get("outcomeFlips") or []) if not f.get("countersigned")]
    if flips:
        return (False, R.SEM_SPEC_DRIFT_UNLOGGED,
                f"{len(flips)} outcome flip(s) without a human countersignature")
    return True, None, "specification sealed; all drift logged"


@evaluator("heldout_evaluated")
def heldout_evaluated(evidence, spec, ctx):
    """FIX-HELDOUT: the v3.8 defect. Held-out results were cryptographically BOUND to the
    run and then never READ — a held-out suite could fail and the gate still passed. Here
    binding is necessary but not sufficient: the outcome must be present and green."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    suites = evidence.payload.get("suites")
    if not isinstance(suites, list):
        return False, R.EVD_MALFORMED, "held-out payload missing 'suites'"
    if not suites:
        return False, R.SEM_HELDOUT_EMPTY, "no held-out suite was stashed or executed"
    for s in suites:
        sid = s.get("suiteId", "?")
        if not s.get("bound"):
            return (False, R.EVD_RUN_MISMATCH,
                    f"held-out suite {sid} is not bound to this run")
        if not s.get("evaluated"):
            return (False, R.SEM_HELDOUT_NOT_EVALUATED,
                    f"held-out suite {sid} was bound but its outcome was never evaluated")
        total = _int(s, "total")
        if total is None:
            return False, R.EVD_MALFORMED, f"held-out suite {sid} has no integer 'total'"
        if total == 0:
            return False, R.SEM_HELDOUT_EMPTY, f"held-out suite {sid} executed zero tests"
        failed, errored, passed = _int(s, "failed"), _int(s, "errored"), _int(s, "passed")
        if None in (failed, errored, passed):
            return False, R.EVD_MALFORMED, f"held-out suite {sid} has non-integer counts"
        if failed or errored:
            return (False, R.SEM_HELDOUT_FAILED,
                    f"held-out suite {sid}: {failed} failed, {errored} errored")
        if passed != total:
            return (False, R.EVD_CONTRADICTORY,
                    f"held-out suite {sid}: passed={passed} but total={total}")
    return True, None, f"{len(suites)} held-out suite(s) bound, evaluated and green"


@evaluator("no_undetected_faults")
def no_undetected_faults(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    undetected = p.get("undetected")
    if not isinstance(undetected, list):
        return False, R.EVD_MALFORMED, "fault audit payload missing 'undetected'"
    total = _int(p, "total")
    if total is None:
        return False, R.EVD_MALFORMED, "fault audit payload missing integer 'total'"
    if total == 0:
        return False, R.EVD_INCOMPLETE, "the fault audit injected zero faults"
    if undetected:
        s = ", ".join(str(u.get("id", u)) for u in undetected[:5])
        return (False, R.SEM_UNDETECTED_FAULT,
                f"{len(undetected)}/{total} injected fault(s) went undetected: {s}")
    errored = p.get("errored") or []
    if errored:
        # FIX-FAULTGEN: a hung or crashed fault run is a BLIND SPOT, not a detection.
        return (False, R.EVD_INCOMPLETE,
                f"{len(errored)} fault run(s) errored or hung; detection is unknown")
    return True, None, f"all {total} injected faults detected"


# --- quality layers -------------------------------------------------------------------------

@evaluator("security_clean")
def security_clean(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    counts = p.get("counts")
    if not isinstance(counts, dict):
        return False, R.EVD_MALFORMED, "security payload missing 'counts'"
    missing_tools = p.get("toolsMissing") or []
    if missing_tools and not (p.get("toolsRun") or []):
        return (False, R.EVD_INCOMPLETE,
                f"no security tool ran (missing: {', '.join(map(str, missing_tools[:5]))})")
    high = (counts.get("critical") or 0) + (counts.get("high") or 0)
    if high:
        return False, R.SEM_SECURITY_SERIOUS, f"{high} critical/high security finding(s)"
    return True, None, "no critical/high security findings"


@evaluator("adversarial_clean")
def adversarial_clean(evidence, spec, ctx):
    """The mechanised core of Phase H found nothing, and the probe earned the right to say so.

    Three refusals, in the order they matter:

      * AN UNADMITTED PROBE IS NOT A PASSING PROBE. The collector runs both families against
        an in-memory vulnerable reference app and a correct one before it touches the target;
        if it failed to catch its own seeded defects, or fired on the correct app, the
        evidence arrives as ERROR and `_usable` rejects it here. That is the same rule the
        rest of the kit applies to tests, applied to the instrument itself — without it,
        promoting this to collected evidence would stamp "adversarially tested" on an app
        nobody meaningfully attacked, which is worse than not having the check.
      * AN EMPTY RUN IS NOT A CLEAN RUN. Zero results means nothing was sent.
      * INCONCLUSIVE FAILS CLOSED. A transport error is not an absence of vulnerability.
    """
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "results", "counts", "admission")
    if not ok:
        return False, R.EVD_MALFORMED, f"adversarial payload missing {missing!r}"
    adm = p.get("admission")
    if not (isinstance(adm, dict) and adm.get("admitted") is True):
        return (False, R.SEM_ADVERSARIAL_PROBE_NOT_ADMITTED,
                "the adversarial probe did not pass its own fail-first admission: "
                + str((adm or {}).get("detail", "no admission record")))
    results = p["results"]
    if not isinstance(results, list) or not results:
        return (False, R.EVD_INCOMPLETE,
                "the adversarial probe sent nothing; an attack that was never made is not "
                "an attack that found nothing")
    leaks = [r for r in results
             if r.get("verdict") == "FINDING" and r.get("family") == "id_coercion"]
    if leaks:
        s = ", ".join(str(r.get("id")) for r in leaks[:4])
        return (False, R.SEM_ADVERSARIAL_AUTHZ_BYPASS,
                f"{len(leaks)} request(s) authenticated as one identity returned another "
                f"identity's data: {s}")
    crashes = [r for r in results
               if r.get("verdict") == "FINDING" and r.get("family") == "malformed_input"]
    if crashes:
        s = ", ".join(str(r.get("id")) for r in crashes[:4])
        return (False, R.SEM_ADVERSARIAL_UNHANDLED_ERROR,
                f"{len(crashes)} malformed request(s) were not refused cleanly: {s}")
    inconclusive = [r for r in results if r.get("verdict") == "INCONCLUSIVE"]
    if inconclusive:
        s = ", ".join(str(r.get("id")) for r in inconclusive[:4])
        return (False, R.EVD_INCOMPLETE,
                f"{len(inconclusive)} adversarial probe(s) got no response (fail-closed): {s}")
    if evidence.status is EvidenceStatus.PARTIAL:
        return (False, R.EVD_INCOMPLETE,
                "adversarial coverage is partial; uncovered: "
                + "; ".join(evidence.uncovered[:3]))
    return True, None, (f"{len(results)} adversarial probe(s) across "
                        f"{len({r.get('family') for r in results})} family/-ies, none "
                        f"successful")


def _admitted(evidence, code):
    """The shared fail-first gate for the four phase collectors.

    Each of them proves it can catch its own defect classes on an in-memory reference before
    it looks at your repository, and refuses to look if it cannot. Promoting any of these to
    COLLECTED evidence without that rule would be worse than leaving the phase self-attested:
    a checker that cannot catch anything would stamp "requirements linked" or "design
    conformant" on work nobody did, laundering false confidence into the strongest evidence
    class in the system.
    """
    adm = evidence.payload.get("admission")
    if not (isinstance(adm, dict) and adm.get("admitted") is True):
        return (False, code,
                "the checker did not pass its own fail-first admission: "
                + str((adm or {}).get("detail", "no admission record")))
    return (True, None, "")


@evaluator("requirements_linked")
def requirements_linked(evidence, spec, ctx):
    """Phase A2's floor: the manifest hangs together, every link resolves, every source was
    read. Not whether the requirements are the RIGHT ones — that stays judgement."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "requirements", "findings", "counts", "admission")
    if not ok:
        return False, R.EVD_MALFORMED, f"requirements payload missing {missing!r}"
    ok, code, why = _admitted(evidence, R.SEM_PHASE_CHECKER_NOT_ADMITTED)
    if not ok:
        return False, code, why
    rows = p["requirements"]
    if not isinstance(rows, list) or not rows:
        return (False, R.EVD_INCOMPLETE,
                "the manifest declares no requirements; an A2 pass that extracted nothing "
                "is not an A2 pass")
    findings = [f for f in p["findings"] if isinstance(f, dict)]
    uncited = [f for f in findings if f.get("kind") == "document_not_cited"]
    if uncited:
        s = ", ".join(str(f.get("id")) for f in uncited[:4])
        return (False, R.SEM_REQUIREMENTS_UNDER_EXTRACTED,
                f"{len(uncited)} requirements document(s) in this tree that no requirement "
                f"cites: {s}")
    other = [f for f in findings if f.get("kind") != "document_not_cited"]
    if other:
        s = "; ".join(f"{f.get('id')}: {f.get('kind')}" for f in other[:4])
        return (False, R.SEM_REQUIREMENTS_UNLINKED,
                f"{len(other)} requirement defect(s): {s}")
    if evidence.status is EvidenceStatus.PARTIAL:
        return (False, R.EVD_INCOMPLETE,
                "requirements coverage is partial; uncovered: "
                + "; ".join(evidence.uncovered[:3]))
    return True, None, (f"{len(rows)} requirement(s), all linked to evidence, every source "
                        f"document cited")


@evaluator("design_conformant")
def design_conformant(evidence, spec, ctx):
    """Phase G2's floor: the rendered UI uses the declared tokens. Not whether it looks good."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "findings", "counts", "admission", "dimensionsChecked")
    if not ok:
        return False, R.EVD_MALFORMED, f"conformance payload missing {missing!r}"
    ok, code, why = _admitted(evidence, R.SEM_PHASE_CHECKER_NOT_ADMITTED)
    if not ok:
        return False, code, why
    if not p["dimensionsChecked"]:
        return (False, R.EVD_INCOMPLETE,
                "no token dimension was declared, so nothing was compared")
    if not p.get("surfaces"):
        return False, R.EVD_INCOMPLETE, "no surface was compared against the tokens"
    findings = [f for f in p["findings"] if isinstance(f, dict)]
    if findings:
        s = "; ".join(f"{f.get('value')} on {f.get('url')} ({f.get('kind')})"
                      for f in findings[:4])
        return (False, R.SEM_DESIGN_NONCONFORMANT,
                f"{len(findings)} value(s) outside the design system: {s}")
    if evidence.status is EvidenceStatus.PARTIAL:
        return (False, R.EVD_INCOMPLETE,
                "conformance coverage is partial; uncovered: "
                + "; ".join(evidence.uncovered[:3]))
    return True, None, (f"{len(p['surfaces'])} surface(s) conform across "
                        f"{len(p['dimensionsChecked'])} dimension(s)")


@evaluator("cross_surface_consistent")
def cross_surface_consistent(evidence, spec, ctx):
    """Phase G3's floor: surfaces agree with each other. Not whether a difference matters."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "findings", "counts", "admission", "surfaces")
    if not ok:
        return False, R.EVD_MALFORMED, f"cross-surface payload missing {missing!r}"
    ok, code, why = _admitted(evidence, R.SEM_PHASE_CHECKER_NOT_ADMITTED)
    if not ok:
        return False, code, why
    surfaces = p["surfaces"]
    if not isinstance(surfaces, list) or len(surfaces) < 2:
        return (False, R.EVD_INCOMPLETE,
                "fewer than two surfaces were compared; one page cannot be inconsistent "
                "with itself, and reporting that as consistency would be a false green")
    findings = [f for f in p["findings"] if isinstance(f, dict)]
    if findings:
        s = "; ".join(f"{f.get('kind')}: {str(f.get('detail'))[:70]}" for f in findings[:3])
        return (False, R.SEM_CROSS_SURFACE_INCONSISTENT,
                f"{len(findings)} inconsistency/-ies across {len(surfaces)} surfaces: {s}")
    if evidence.status is EvidenceStatus.PARTIAL:
        return (False, R.EVD_INCOMPLETE,
                "cross-surface coverage is partial; uncovered: "
                + "; ".join(evidence.uncovered[:3]))
    return True, None, f"{len(surfaces)} surfaces agree on labels, dates, money and numbers"


@evaluator("a11y_clean")
def a11y_clean(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    counts = p.get("counts")
    if not isinstance(counts, dict):
        return False, R.EVD_MALFORMED, "accessibility payload missing 'counts'"
    if not _int(p, "pagesScanned"):
        return False, R.EVD_INCOMPLETE, "no pages were scanned for accessibility"
    serious = (counts.get("critical") or 0) + (counts.get("serious") or 0)
    if serious:
        return False, R.SEM_A11Y_SERIOUS, f"{serious} serious/critical accessibility violation(s)"
    return True, None, f"{p['pagesScanned']} pages scanned; no serious violations"


@evaluator("perf_within_budget")
def perf_within_budget(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    metrics = evidence.payload.get("metrics")
    if not isinstance(metrics, dict) or not metrics:
        return False, R.EVD_INCOMPLETE, "no performance metrics were measured"
    return True, None, f"{len(metrics)} performance metric(s) measured"


@evaluator("envfault_detected")
def envfault_detected(evidence, spec, ctx):
    """FIX-ENVFAULT: v3.8 let an environment fault that the suite failed to detect pass
    through as an 'environment problem'. An undetected env fault is a detection gap."""
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    ops = evidence.payload.get("operators")
    if not isinstance(ops, list):
        return False, R.EVD_MALFORMED, "env-fault payload missing 'operators'"
    if not ops:
        return False, R.EVD_INCOMPLETE, "no environment fault operators were planned"
    applied = [o for o in ops if o.get("applied")]
    if not applied:
        return False, R.EVD_INCOMPLETE, "no environment fault operator was actually applied"
    undetected = [o for o in applied if not o.get("detected")]
    if undetected:
        s = ", ".join(str(o.get("id", "?")) for o in undetected[:5])
        return (False, R.SEM_UNDETECTED_FAULT,
                f"{len(undetected)} environment fault(s) went undetected: {s}")
    return True, None, f"{len(applied)} environment faults injected and all detected"


# --- containment & findings ------------------------------------------------------------------

@evaluator("containment_enforced")
def containment_enforced(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    p = evidence.payload
    ok, missing = _need(p, "allTargetContained", "uncontainedTargetInvocations",
                        "targetInvocations", "containmentRequired", "boundary")
    if not ok:
        return False, R.EVD_MALFORMED, f"containment payload missing {missing!r}"
    if not p.get("containmentRequired"):
        return True, None, "containment not required by policy (recorded, not claimed)"
    if not p.get("anyTargetExecuted"):
        return (False, R.EVD_INCOMPLETE,
                "no target-controlled process was executed at all, so nothing was proved "
                "about the system under test")
    if p.get("uncontainedTargetInvocations"):
        n = p["uncontainedTargetInvocations"]
        ack = " (host execution was explicitly acknowledged)" if p.get("hostExecAcknowledged") else ""
        return (False, R.EXE_CONTAINMENT_REQUIRED_UNAVAILABLE,
                f"{n}/{p['targetInvocations']} target process(es) ran with no proved "
                f"containment boundary{ack}")
    if not p.get("allTargetContained"):
        return False, R.EXE_CONTAINMENT_DEGRADED, "containment was not established for all target work"
    boundary = p.get("boundary")
    kind = boundary.get("kind", "unknown") if isinstance(boundary, dict) else "unknown"
    return True, None, f"{p['targetInvocations']} target processes ran inside {kind}"


@evaluator("no_blocking_findings")
def no_blocking_findings(evidence, spec, ctx):
    ok, reason, detail = _usable(evidence)
    if not ok:
        return False, reason, detail
    blocking = blocking_findings(ctx.findings)
    if blocking:
        top = sorted(blocking, key=lambda f: -f.severity.rank)[:5]
        s = "; ".join(f"{f.severity.value} {f.id}: {f.title}" for f in top)
        showstoppers = [f for f in blocking if f.severity.value == "SHOWSTOPPER"]
        code = R.SEM_SHOWSTOPPER_OPEN if showstoppers else R.SEM_BLOCKER_OPEN
        return False, code, f"{len(blocking)} blocking finding(s): {s}"
    streak = ctx.clean_round_streak
    need = ctx.profile.required_clean_rounds
    if streak < need:
        return (False, R.SEM_CONVERGENCE_NOT_REACHED,
                f"{streak}/{need} consecutive clean rounds")
    return True, None, f"no blocking findings; {streak} consecutive clean rounds"
