"""FINDINGS collector — the defect record, parsed through the typed model.

There is no v3.8 file to port here: v3.8 kept findings inside `gate.py`'s state as loose
dicts, which is exactly why a waiver on a non-waivable severity could be written by hand and
never challenged. This collector loads `<workdir>/findings.json` and parses every entry
through `models.finding.Finding`, whose `__post_init__` REFUSES a waived SHOWSTOPPER/CRITICAL,
refuses a waived CUJ finding, and refuses a waiver with no reason and no named authority.

A malformed or dishonest findings file therefore RAISES, which `Collector.run` turns into
ERROR evidence — the gate fails closed rather than accepting a record it could not validate.

FIX-FINDINGS-STREAK-COMPUTED: the clean-round streak is COMPUTED from the round history and
the findings actually present, never read from a `cleanRoundStreak` field in the file. A
self-declared streak is the cheapest possible way to satisfy the convergence requirement, and
`no_blocking_findings` reads that streak directly.

FIX-FINDINGS-CURRENT-ROUND-IS-MEASURED: the entry for the CURRENT round is derived from the
findings in front of us, overriding whatever the file claims about it. A round recorded as
"clean" while a blocking finding sits in the same file is not a clean round.

Filesystem reads only; no process is spawned.
"""
import json
from pathlib import Path

from ..models.evidence import EvidenceKind
from ..models.finding import Finding, FindingState, Severity, blocking_findings, summarise
from .base import Collector


def _severity(value):
    try:
        return Severity(str(value).upper())
    except ValueError:
        raise ValueError(
            f"unknown severity {value!r}; a finding whose severity cannot be read cannot be "
            f"ranked, and an unrankable finding must never default to a low one") from None


def _state(value):
    if value is None or value == "":
        return FindingState.OPEN
    try:
        return FindingState(str(value).upper())
    except ValueError:
        raise ValueError(f"unknown finding state {value!r}") from None


def _get(doc, *names, default=None):
    for n in names:
        if n in doc:
            return doc[n]
    return default


def finding_from_json(doc, index=0):
    """Build a typed Finding. Raises on anything that cannot be validated."""
    if not isinstance(doc, dict):
        raise ValueError(f"findings[{index}] is not an object")
    fid = str(_get(doc, "id", default="") or f"finding-{index + 1}")
    refs = _get(doc, "evidenceRefs", "evidence_refs", default=()) or ()
    if not isinstance(refs, (list, tuple)):
        raise ValueError(f"finding {fid}: evidenceRefs is not a list")
    kwargs = {
        "id": fid,
        "severity": _severity(_get(doc, "severity", default="MAJOR")),
        "state": _state(_get(doc, "state")),
        "title": str(_get(doc, "title", default="") or ""),
        "detail": str(_get(doc, "detail", "description", default="") or ""),
        "source": str(_get(doc, "source", default="") or ""),
        "reason_code": _get(doc, "reasonCode", "reason_code"),
        "location": _get(doc, "location"),
        "evidence_refs": tuple(str(r) for r in refs),
        "reason": _get(doc, "reason"),
        "authority": _get(doc, "authority"),
        "cuj": bool(_get(doc, "cuj", default=False)),
    }
    recorded = _get(doc, "recordedAt", "recorded_at")
    if recorded:
        kwargs["recorded_at"] = str(recorded)
    return Finding(**kwargs)   # raises for an unwaivable waiver / a reasonless one


def _rounds(doc):
    raw = doc.get("rounds") if isinstance(doc, dict) else None
    out = []
    if isinstance(raw, list):
        for i, r in enumerate(raw):
            if not isinstance(r, dict):
                continue
            n = r.get("round", r.get("index", i + 1))
            new_blocking = r.get("newBlocking", r.get("new_blocking", 0))
            out.append({
                "round": int(n) if isinstance(n, int) and not isinstance(n, bool) else i + 1,
                "newBlocking": int(new_blocking)
                if isinstance(new_blocking, int) and not isinstance(new_blocking, bool) else 0,
                "clean": bool(r.get("clean", False)),
            })
    return out


def clean_round_streak(rounds):
    """Consecutive clean rounds at the END of the history. Computed, never claimed."""
    streak = 0
    for r in reversed(rounds):
        if r.get("clean"):
            streak += 1
        else:
            break
    return streak


class FindingsCollector(Collector):
    """Load, validate and summarise the run's findings.

    Options: `findings` (an explicit list), `findings_file`
    (default `<workdir>/findings.json`).
    """

    kind = EvidenceKind.FINDINGS
    name = "findings"
    version = "4.2.4"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        path = Path(ctx.option("findings_file") or (workdir / "findings.json"))
        rnd = int(getattr(ctx.binding, "round_index", 0) or 0)

        explicit = ctx.option("findings")
        doc = None
        uncovered = []
        if isinstance(explicit, (list, dict)):
            doc = explicit
        elif path.exists():
            try:
                doc = json.loads(path.read_text())
            except Exception as exc:  # noqa: BLE001
                return self.error(ctx, f"{path} is not readable JSON ({type(exc).__name__}: {exc}); "
                                       f"an unreadable defect record is not an empty one")
        else:
            uncovered.append(f"findings: no record at {path}, so no defect history could be read")

        raw = []
        if isinstance(doc, list):
            raw = doc
        elif isinstance(doc, dict):
            if isinstance(doc.get("findings"), list):
                raw = doc["findings"]
            elif isinstance(doc.get("items"), list):
                raw = doc["items"]

        findings = [finding_from_json(f, i) for i, f in enumerate(raw)]
        blocking = blocking_findings(findings)

        rounds = _rounds(doc if isinstance(doc, dict) else {})
        # FIX-FINDINGS-CURRENT-ROUND-IS-MEASURED
        measured = {"round": rnd, "newBlocking": len(blocking), "clean": not blocking}
        rounds = [r for r in rounds if r["round"] != rnd]
        rounds.append(measured)
        rounds.sort(key=lambda r: r["round"])

        payload = {
            "findings": [f.to_json() for f in findings],
            "rounds": rounds,
            # FIX-FINDINGS-STREAK-COMPUTED
            "cleanRoundStreak": clean_round_streak(rounds),
            "summary": summarise(findings),
            "source": ("option:findings" if isinstance(explicit, (list, dict))
                       else str(path)),
        }
        note = (f"{len(findings)} finding(s), {len(blocking)} blocking; "
                f"{payload['cleanRoundStreak']} consecutive clean round(s)")
        return self.collected(ctx, payload, note=note, uncovered=uncovered)
