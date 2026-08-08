"""Self-contained HTML report — the human deliverable.

One file, no network, no external CSS or fonts, no scripts that fetch anything. It is meant
to be opened from disk, attached to a ticket, or archived, and it must render identically
years later.

The two axes are shown as two separate badges. There is deliberately no single green
"PASSED" hero: conflating "it works" with "someone external vouched for it" is precisely
the confusion v4.0 exists to remove.
"""
import html as _html

from ..models.decision import ProvenanceStatus, derive_outcome

_CSS = """
:root{--bg:#0f1115;--panel:#161a21;--line:#242a35;--txt:#e6e9ef;--dim:#98a2b3;
--ok:#3ddc97;--bad:#ff6b6b;--warn:#ffc857;--na:#5b6472;--acc:#7aa2f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 72px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 10px;
text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
.sub{color:var(--dim);font-size:13px;margin-bottom:24px}
.axes{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}
.axis{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.axis .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
.axis .v{font-size:19px;font-weight:650;margin-top:4px}
.axis .n{font-size:12px;color:var(--dim);margin-top:6px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.na{color:var(--na)}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);
vertical-align:top;font-size:13px}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
tr:last-child td{border-bottom:none}
td.s{width:64px;font-weight:700;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;background:var(--panel);
border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kv .k{color:var(--dim);font-size:12px}
.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:8px;padding:12px 14px;color:var(--dim);font-size:13px;margin:12px 0}
.note.bad{border-left-color:var(--bad)}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;
border:1px solid var(--line);color:var(--dim)}
.foot{margin-top:40px;color:var(--dim);font-size:12px;word-break:break-all}
"""


def _e(v):
    return _html.escape("" if v is None else str(v), quote=True)


def render(decision, attestation=None):
    d = decision
    prov = attestation.provenance_status if attestation else ProvenanceStatus.NONE
    outcome = derive_outcome(d.semantic_status, prov)

    sem_cls = "ok" if d.semantic_status.value == "PASSED" else "bad"
    prov_cls = {"NONE": "na", "UNAVAILABLE": "warn",
                "CI_ATTESTED": "ok", "INDEPENDENTLY_ATTESTED": "ok"}[prov.value]
    out_cls = {"VERIFIED": "ok", "CI_ATTESTED": "ok", "INDEPENDENTLY_ATTESTED": "ok",
               "AUTHORITY_UNAVAILABLE": "warn", "FAILED": "bad"}[outcome.value]

    p = []
    p.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    p.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    p.append(f"<title>ship-gate report — {_e(d.subject.repository)}</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")
    p.append(f"<h1>ship-gate report — {_e(d.subject.repository)}</h1>")
    p.append(f"<div class='sub'>{_e(d.engine)} &middot; decision "
             f"<span class='mono'>{_e(d.decision_id)}</span> &middot; {_e(d.created_at)} "
             f"&middot; profile <span class='pill'>{_e(d.profile_id)}</span> "
             f"&middot; mode <span class='pill'>{_e(d.mode)}</span></div>")

    p.append("<div class='axes'>")
    p.append(_axis("Semantic — Axis B", d.semantic_status.value, sem_cls,
                   "Does the evidence prove the run passed its required checks?"))
    p.append(_axis("Provenance — Axis A", prov.value, prov_cls,
                   "Is the evidence authentic, fresh, policy-bound and identity-bound?"))
    cov_suffix = d.coverage_suffix
    p.append(_axis("Outcome (derived)",
                   outcome.value + (f" — {cov_suffix}" if cov_suffix else ""), out_cls,
                   f"exit code {_exit(outcome)}"))
    p.append("</div>")

    if cov_suffix:
        p.append("<div class='note warn'><strong>Coverage is partial.</strong> "
                 + _e(cov_suffix[0].upper() + cov_suffix[1:])
                 + ". The outcome above is the verdict on the evidence that WAS collected; "
                   "it is not a statement that the whole procedure was performed. See "
                   "<em>Phase coverage</em> below.</div>")

    if prov is ProvenanceStatus.NONE:
        p.append("<div class='note'><strong>No provenance authority is claimed.</strong> "
                 "VERIFIED means the semantic decision passed on its merits. It says nothing "
                 "about who produced the evidence. Authentic evidence does not imply semantic "
                 "success, and semantic success alone does not establish authority.</div>")
    elif prov is ProvenanceStatus.UNAVAILABLE:
        p.append("<div class='note'><strong>External authority was requested but is "
                 "unavailable</strong> — absent, unsupported, or unqualified. The VERIFIED "
                 "semantic result remains usable exactly as it stands.</div>")

    if d.break_glass:
        bg = d.break_glass
        p.append(f"<div class='note bad'><strong>BREAK-GLASS OVERRIDE RECORDED.</strong> "
                 f"authority <code>{_e(bg.get('authority'))}</code>, ticket "
                 f"<code>{_e(bg.get('ticket'))}</code>. {_e(bg.get('reason'))} "
                 f"A break-glass run is audited and is never reported as VERIFIED.</div>")

    if d.coverage is not None:
        cov = d.coverage.to_json()
        p.append("<h2>Phase coverage <span class='pill'>self-attested</span></h2>")
        p.append("<div class='note'>What the <strong>operating agent</strong> says it did. "
                 "This is the weakest input in the run, so it is held to a one-way rule: it "
                 "can only ever <strong>subtract</strong> from how the outcome reads, never "
                 "add to it, and a caveat is cleared by a <strong>collector</strong> — never "
                 "by a claim. A phase nobody mentioned is recorded as <em>not run</em>.</div>")
        p.append("<table><tr><th>State</th><th>Phase</th><th>What it covers</th></tr>")
        for c in cov["phases"]:
            if c["corroborated"]:
                cls, label = "ok", "COLLECTED"
            elif c["claim"] == "run":
                cls, label = "warn", "SELF-REPORTED"
            else:
                cls, label = "bad", "NOT RUN"
            p.append(f"<tr><td class='s {cls}'>{label}</td>"
                     f"<td><code>{_e(c['phase'])}</code></td>"
                     f"<td>{_e(c['title'])}</td></tr>")
        p.append("</table>")
        if cov["note"]:
            p.append(f"<div class='sub'>{_e(cov['note'])}</div>")

    s = d.subject
    p.append("<h2>Subject</h2><div class='kv'>")
    for k, v in (("repository", s.repository), ("branch", s.branch), ("commit", s.commit),
                 ("tree digest", s.tree_digest), ("artifact", s.artifact_id),
                 ("artifact digest", s.artifact_digest),
                 ("profile digest", d.profile_digest)):
        p.append(f"<div class='k'>{_e(k)}</div><div class='mono'>{_e(v)}</div>")
    p.append("</div>")

    p.append("<h2>Checks</h2><table><tr><th>Result</th><th>Check</th><th>Detail</th></tr>")
    for c in d.checks:
        na = c.passed and "not applicable" in (c.detail or "")
        cls, label = ("na", "N/A") if na else (("ok", "PASS") if c.passed else ("bad", "FAIL"))
        extra = " <span class='pill'>showstopper</span>" if c.showstopper else ""
        det = _e(c.detail)
        if c.reason_code:
            det = f"<code>{_e(c.reason_code)}</code> — {det}"
        p.append(f"<tr><td class='s {cls}'>{label}</td><td>{_e(c.title)}<br>"
                 f"<code>{_e(c.check_id)}</code>{extra}</td><td>{det}</td></tr>")
    p.append("</table>")

    p.append("<h2>Thresholds</h2><table>"
             "<tr><th>Result</th><th>Threshold</th><th>Required</th><th>Measured</th></tr>")
    for t in d.thresholds:
        cls, label = ("ok", "PASS") if t.passed else ("bad", "FAIL")
        got = "<span class='warn'>unmeasured</span>" if t.measured_value is None \
            else f"{_e(t.measured_value)}{_e(t.unit)}"
        p.append(f"<tr><td class='s {cls}'>{label}</td><td><code>{_e(t.threshold_id)}</code><br>"
                 f"{_e(t.metric)}</td><td>{_e(t.comparison)} {_e(t.required_value)}"
                 f"{_e(t.unit)}</td><td>{got}</td></tr>")
    p.append("</table>")

    if d.cujs:
        p.append("<h2>Critical user journeys</h2><table>"
                 "<tr><th>Result</th><th>Journey</th><th>Detail</th></tr>")
        for c in d.cujs:
            cls, label = ("ok", "PASS") if c.evidenced else ("bad", "FAIL")
            p.append(f"<tr><td class='s {cls}'>{label}</td><td>{_e(c.title)}<br>"
                     f"<code>{_e(c.id)}</code></td><td>{_e(c.status)} — {_e(c.detail)}</td></tr>")
        p.append("</table>")

    if d.heldout:
        p.append("<h2>Held-out suites</h2><table><tr><th>Result</th><th>Suite</th>"
                 "<th>Bound</th><th>Evaluated</th><th>Counts</th></tr>")
        for h in d.heldout:
            cls, label = ("ok", "PASS") if h.green else ("bad", "FAIL")
            p.append(f"<tr><td class='s {cls}'>{label}</td><td><code>{_e(h.suite_id)}</code></td>"
                     f"<td>{_e(h.bound)}</td><td>{_e(h.evaluated)}</td>"
                     f"<td>{_e(h.passed)}/{_e(h.total)} passed, {_e(h.failed)} failed, "
                     f"{_e(h.errored)} errored</td></tr>")
        p.append("</table>")

    if d.findings:
        blocking = sum(1 for f in d.findings if f.blocks)
        p.append(f"<h2>Findings — {blocking} blocking of {len(d.findings)}</h2><table>"
                 "<tr><th>Severity</th><th>State</th><th>Finding</th></tr>")
        for f in sorted(d.findings, key=lambda x: -x.severity.rank):
            cls = "bad" if f.blocks else "na"
            cuj = " <span class='pill'>CUJ</span>" if f.cuj else ""
            p.append(f"<tr><td class='s {cls}'>{_e(f.severity.value)}</td>"
                     f"<td>{_e(f.state.value)}{' (blocking)' if f.blocks else ''}</td>"
                     f"<td><strong>{_e(f.title)}</strong>{cuj}<br>{_e(f.detail)}"
                     f"{f'<br><code>{_e(f.reason_code)}</code>' if f.reason_code else ''}</td></tr>")
        p.append("</table>")

    b = (d.containment or {}).get("boundary") or {}
    p.append("<h2>Execution containment</h2><div class='kv'>")
    for k, v in (("boundary", b.get("kind")), ("established", b.get("established")),
                 ("required", d.containment.get("containmentRequired")),
                 ("target invocations", d.containment.get("targetInvocations")),
                 ("uncontained", d.containment.get("uncontainedTargetInvocations")),
                 ("timeouts", d.containment.get("timeouts")),
                 ("output-limit kills", d.containment.get("outputLimitHits")),
                 ("host exec acknowledged", d.containment.get("hostExecAcknowledged"))):
        p.append(f"<div class='k'>{_e(k)}</div><div class='mono'>{_e(v)}</div>")
    p.append("</div>")

    p.append("<h2>Evidence received</h2><table>"
             "<tr><th>Kind</th><th>Collector</th><th>Status</th><th>Collected</th></tr>")
    for e in d.received_evidence:
        st = e.get("status")
        cls = {"COLLECTED": "ok", "PARTIAL": "warn"}.get(st, "bad")
        p.append(f"<tr><td><code>{_e(e.get('kind'))}</code></td><td>{_e(e.get('collector'))}</td>"
                 f"<td class='{cls}'>{_e(st)}</td><td class='mono'>{_e(e.get('collectedAt'))}</td></tr>")
    p.append("</table>")

    if attestation:
        p.append("<h2>Attestation</h2><div class='kv'>")
        for k, v in (("verifier", attestation.verifier),
                     ("verifier version", attestation.verifier_version),
                     ("provenance status", attestation.provenance_status.value),
                     ("binds to decision", attestation.decision_digest),
                     ("reason codes", ", ".join(attestation.reason_codes)),
                     ("detail", attestation.detail)):
            p.append(f"<div class='k'>{_e(k)}</div><div class='mono'>{_e(v)}</div>")
        p.append("</div>")

    p.append("<h2>Reason codes</h2><div class='kv'>")
    for code in d.reason_codes:
        p.append(f"<div class='k mono'>{_e(code)}</div><div></div>")
    p.append("</div>")

    p.append("<h2>Residual risk</h2>")
    if d.residual_risk:
        p.append(f"<div class='note'>{_e(d.residual_risk)}</div>")
    else:
        p.append("<div class='note bad'>NOT RECORDED. A report without a named residual "
                 "risk is incomplete.</div>")

    p.append(f"<div class='foot'>decision digest "
             f"<span class='mono'>{_e(d.digest())}</span><br>"
             f"schema {_e(d.schema)} &middot; engine {_e(d.engine)}</div>")
    p.append("</div></body></html>")
    return "".join(p)


def _axis(key, value, cls, note):
    return (f"<div class='axis'><div class='k'>{_e(key)}</div>"
            f"<div class='v {cls}'>{_e(value)}</div><div class='n'>{_e(note)}</div></div>")


def _exit(outcome):
    from ..models.decision import EXIT_CODES
    return EXIT_CODES[outcome]
