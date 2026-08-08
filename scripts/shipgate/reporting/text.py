"""Plain-text rendering of a decision — what a developer or a CI log sees.

The two axes are printed SEPARATELY and the outcome is printed as derived. There is no
line in this output that a consumer could grep for the word "PASS" and be misled by:
machine consumers read `outcome`, `semanticStatus`, `provenanceStatus` and the exit code.
"""
from ..models.decision import Outcome, ProvenanceStatus

_TICK = "PASS"
_CROSS = "FAIL"
_SKIP = "n/a "


def render(decision, attestation=None, width=96):
    d = decision
    out = []
    bar = "=" * width
    out.append(bar)
    out.append(f"ship-gate {d.engine}  |  decision {d.decision_id}")
    out.append(bar)

    prov = attestation.provenance_status if attestation else ProvenanceStatus.NONE
    outcome = _outcome(d, prov)
    out.append("")
    out.append(f"  SEMANTIC   (Axis B, does it work?)   : {d.semantic_status.value}")
    out.append(f"  PROVENANCE (Axis A, who says so?)    : {prov.value}")
    suffix = d.coverage_suffix
    out.append(f"  OUTCOME    (derived)                 : {outcome.value}"
               + (f" — {suffix}" if suffix else ""))
    out.append(f"  EXIT CODE                            : {_exit(outcome)}")
    out.append(f"  MODE                                 : {d.mode}")
    if prov is ProvenanceStatus.NONE:
        out.append("  note: no external authority was claimed. VERIFIED means the semantic")
        out.append("        decision passed — it asserts nothing about provenance.")
    out.append("")

    out.append(_section("SUBJECT"))
    s = d.subject
    out.append(f"  repository   {s.repository}")
    out.append(f"  commit       {s.commit}")
    out.append(f"  tree digest  {s.tree_digest}")
    out.append(f"  artifact     {s.artifact_id} @ {(s.artifact_digest or '')[:32]}…")
    out.append(f"  profile      {d.profile_id} @ {d.profile_digest[:16]}…")
    out.append("")

    out.append(_section("CHECKS"))
    for c in d.checks:
        mark = _TICK if c.passed else _CROSS
        if c.passed and "not applicable" in (c.detail or ""):
            mark = _SKIP
        flag = " [SHOWSTOPPER]" if c.showstopper and not c.passed else ""
        out.append(f"  [{mark}] {c.check_id:28s} {c.title}{flag}")
        if not c.passed:
            out.append(f"         -> {c.reason_code}: {c.detail}")
    out.append("")

    out.append(_section("THRESHOLDS"))
    for t in d.thresholds:
        mark = _TICK if t.passed else _CROSS
        got = "unmeasured" if t.measured_value is None else f"{t.measured_value}{t.unit}"
        out.append(f"  [{mark}] {t.threshold_id:28s} {t.metric} {t.comparison} "
                   f"{t.required_value}{t.unit}; measured {got}")
    out.append("")

    if d.cujs:
        out.append(_section("CRITICAL USER JOURNEYS"))
        for c in d.cujs:
            out.append(f"  [{_TICK if c.evidenced else _CROSS}] {c.id:28s} {c.title} "
                       f"({c.status})")
        out.append("")

    if d.heldout:
        out.append(_section("HELD-OUT SUITES"))
        for h in d.heldout:
            out.append(f"  [{_TICK if h.green else _CROSS}] {h.suite_id:28s} "
                       f"bound={h.bound} evaluated={h.evaluated} "
                       f"{h.passed}/{h.total} passed, {h.failed} failed, {h.errored} errored")
        out.append("")

    blocking = [f for f in d.findings if f.blocks]
    if d.findings:
        out.append(_section(f"FINDINGS ({len(blocking)} blocking of {len(d.findings)})"))
        for f in sorted(d.findings, key=lambda x: -x.severity.rank)[:25]:
            state = f"{f.state.value}{' BLOCKING' if f.blocks else ''}"
            out.append(f"  {f.severity.value:12s} {f.id:14s} {state:18s} {f.title}")
            if f.detail:
                out.append(f"               {f.detail[:110]}")
        out.append("")

    out.append(_section("PHASE COVERAGE (SELF-ATTESTED)"))
    if d.coverage is None:
        out.append("  no phase record was produced by this engine build")
    else:
        cov = d.coverage
        out.append("  What the OPERATING AGENT says it did. This is the weakest input in the")
        out.append("  run: it can only ever SUBTRACT from how the outcome reads, and only a")
        out.append("  COLLECTOR — never a claim — can clear a caveat.")
        out.append("")
        for c in cov.to_json()["phases"]:
            if c["corroborated"]:
                mark, state = _TICK, "COLLECTED"
            elif c["claim"] == "run":
                mark, state = "SELF", "self-reported, not collected"
            else:
                mark, state = _CROSS, "NOT RUN"
            out.append(f"  [{mark}] phase {c['phase']:3s} {state}")
            if c["title"]:
                out.append(f"         {c['title'][:100]}")
        out.append("")
        out.append(f"  coverage complete (all phases COLLECTED): {cov.complete()}")
    out.append("")

    out.append(_section("CONTAINMENT"))
    b = (d.containment or {}).get("boundary") or {}
    out.append(f"  boundary            {b.get('kind', 'unknown')} "
               f"(established={b.get('established')})")
    out.append(f"  target invocations  {d.containment.get('targetInvocations', '?')} "
               f"({d.containment.get('uncontainedTargetInvocations', '?')} uncontained)")
    out.append("")

    out.append(_section("REASON CODES"))
    for code in d.reason_codes:
        out.append(f"  {code}")
    out.append("")

    if d.break_glass:
        out.append(_section("BREAK-GLASS (AUDITED)"))
        bg = d.break_glass
        out.append(f"  authority {bg.get('authority')}   ticket {bg.get('ticket')}")
        out.append(f"  reason    {bg.get('reason')}")
        out.append("  A break-glass run is recorded and is NEVER reported as VERIFIED.")
        out.append("")

    if attestation:
        out.append(_section("ATTESTATION"))
        out.append(f"  verifier    {attestation.verifier} {attestation.verifier_version}")
        out.append(f"  binds to    {attestation.decision_digest[:32]}…")
        out.append(f"  reasons     {', '.join(attestation.reason_codes)}")
        if attestation.detail:
            out.append(f"  detail      {attestation.detail[:200]}")
        out.append("")

    out.append(_section("RESIDUAL RISK"))
    out.append(f"  {d.residual_risk or '(NOT RECORDED — the report is incomplete without it)'}")
    out.append("")
    out.append(f"decision digest: {d.digest()}")
    out.append(bar)
    return "\n".join(out)


def _section(title):
    return f"-- {title} " + "-" * max(0, 90 - len(title))


def _outcome(decision, prov):
    from ..models.decision import derive_outcome
    return derive_outcome(decision.semantic_status, prov)


def _exit(outcome):
    from ..models.decision import EXIT_CODES
    return EXIT_CODES[outcome]
