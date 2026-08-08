"""SPEC_SEAL collector — the specification is load-bearing, so it is sealed too.

Ported from v3.8 `spec_seal.py`. The model is unchanged, deliberately mirroring the test
seal's immutable-baseline + append-only-log pattern:

  * `baseline` : spec-v0, sealed ONCE, before any implementation is judged against it. Never
                 rewritten. Every later state is diffed against it.
  * `log`      : every subsequent reseal appends {at, reason, sha256, added, flipped,
                 countersign}. Append-only; a later seal cannot erase an earlier delta.
  * classification: an ADDITIVE DISCOVERY (new expectation appears) needs only a reason; an
                 OUTCOME FLIP (an existing condition's expected RESULT changes) needs a human
                 countersignature, because a spec bent to match the code is the oracle problem
                 itself. `_RESULT_MARKER` and `_classify` are ported verbatim, including the
                 deliberately conservative treatment of a deleted result line as a flip.

NOT PORTED — and deliberately so: v3.8's `_verify_detached()` spawned an external crypto tool
to check a detached countersignature against a registered public key. That belongs to the
trust-and-identity layer, which is out of scope for these Axis-B collectors, and the semantic
layer does not consume the cryptographic claim at all. What the payload carries is the
recorded fact — `countersigned: true/false` — taken from the append-only log. An
un-countersigned flip is reported as `countersigned: false`, which `spec_sealed` fails on, so
the fail-closed behaviour is unchanged; only the STRENGTH of the countersignature is reduced
from "verified by key" to "recorded human approval".

Filesystem reads and writes inside the run area only; no process is spawned.
"""
import difflib
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from ..util.clock import utcnow_iso
from ..util.hashing import sha256_text
from .base import Collector

SPEC_SEAL_VERSION = 2

#: v3.8 verbatim. A line asserting an EXPECTED RESULT; changing one after v0 is an outcome flip.
_RESULT_MARKER = re.compile(
    r"\b(should|must|expect|returns?|rejects?|denies|allows?|forbids?|blocks?|"
    r"succeeds?|fails?|equals?|is\s+(?:visible|hidden|enabled|disabled|allowed|denied))\b",
    re.I)

#: Where a specification lives when the caller does not name one.
SPEC_CANDIDATES = (
    "spec.md", "SPEC.md", "docs/spec.md", "docs/SPEC.md", "shipgate-workdir/spec.md",
    "specification.md", "docs/specification.md", "requirements.md", "docs/requirements.md",
)


def classify(old_text, new_text):
    """v3.8 `_classify`: (added_lines, flipped_result_lines) between v0 and the current text."""
    old = old_text.splitlines()
    new = new_text.splitlines()
    sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    added, flipped = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "insert":
            added += [l for l in new[j1:j2] if l.strip()]
        elif tag == "replace":
            old_block = [l for l in old[i1:i2] if l.strip()]
            new_block = [l for l in new[j1:j2] if l.strip()]
            for ol in old_block:
                if _RESULT_MARKER.search(ol):
                    flipped.append(ol.strip())
            added += [l for l in new_block if l not in old_block]
        elif tag == "delete":
            # An expectation REMOVED is a flip in spirit; treat it as one (v3.8 comment kept).
            for ol in old[i1:i2]:
                if _RESULT_MARKER.search(ol):
                    flipped.append(ol.strip())
    return added, flipped


def _load(path):
    try:
        doc = json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None
    return doc if isinstance(doc, dict) else None


def find_spec(root, workdir, declared):
    if declared:
        p = Path(declared)
        p = p if p.is_absolute() else (Path(root) / p)
        return p if p.is_file() else None
    for rel in SPEC_CANDIDATES:
        p = Path(root) / rel
        if p.is_file():
            return p
    for base in (Path(workdir), Path(root)):
        try:
            for p in sorted(base.glob("*.md")):
                if p.stem.lower() in ("spec", "specification"):
                    return p
        except OSError:
            continue
    return None


class SpecSealCollector(Collector):
    """Seal spec-v0 once, then report every drift from it and whether the drift was logged.

    Options: `spec_path`, `vault` (default `<workdir>/.vault`), `spec_reseal_reason`,
    `spec_countersign` (a recorded human approval for an outcome flip).
    """

    kind = EvidenceKind.SPEC_SEAL
    name = "spec-seal"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        vault = Path(ctx.option("vault") or (workdir / ".vault"))
        baseline_path = vault / "spec-baseline.json"

        spec = find_spec(root, workdir, ctx.option("spec_path"))
        bl = _load(baseline_path)

        if spec is None:
            # No spec at all. The load-bearing artifact is missing, so it is certainly not
            # sealed — reported honestly rather than defaulted to sealed.
            return self.collected(ctx, {
                "sealed": False,
                "specPath": "",
                "baselineDigest": (bl or {}).get("sha256", "") if bl else "",
                "currentDigest": "",
                "driftLogged": False,
                "unloggedDeltas": [],
                "outcomeFlips": [],
            }, note="no specification file was found; searched "
                    + ", ".join(SPEC_CANDIDATES[:4]) + ", ...",
               uncovered=["specification: no spec file to seal"])

        try:
            text = spec.read_text(errors="ignore")
        except OSError as exc:
            return self.error(ctx, f"specification {spec} is unreadable: {type(exc).__name__}: {exc}")
        current_digest = sha256_text(text)
        rel_spec = str(spec.relative_to(root)) if str(spec).startswith(str(root)) else str(spec)

        if bl is None:
            # Seal spec-v0 ONCE. It is immutable from here; every later edit is a recorded delta.
            doc = {"spec_seal_version": SPEC_SEAL_VERSION, "sealed_at": utcnow_iso(),
                   "spec_path": rel_spec, "sha256": current_digest, "text": text, "log": []}
            try:
                vault.mkdir(parents=True, exist_ok=True)
                baseline_path.write_text(json.dumps(doc, indent=2))
            except OSError as exc:
                return self.error(ctx, f"could not seal spec-v0 at {baseline_path}: "
                                       f"{type(exc).__name__}: {exc}")
            return self.collected(ctx, {
                "sealed": True,
                "specPath": rel_spec,
                "baselineDigest": current_digest,
                "currentDigest": current_digest,
                "driftLogged": True,
                "unloggedDeltas": [],
                "outcomeFlips": [],
            }, note=f"spec-v0 sealed ({len(text.splitlines())} lines, {current_digest[:12]}); "
                    f"this baseline is immutable")

        base_text = bl.get("text")
        base_digest = bl.get("sha256")
        if not isinstance(base_text, str) or not isinstance(base_digest, str):
            return self.error(ctx, f"spec baseline at {baseline_path} is malformed (no text/sha256); "
                                   f"the specification cannot be shown to be sealed")
        log = [e for e in (bl.get("log") or []) if isinstance(e, dict)]
        added, flipped = classify(base_text, text)

        # --- record this state, if the caller supplied a reason -------------------------------
        reason = (ctx.option("spec_reseal_reason") or "").strip()
        countersign = (ctx.option("spec_countersign") or "").strip()
        logged_shas = {e.get("sha256") for e in log}
        if reason and current_digest != base_digest and current_digest not in logged_shas:
            entry = {"at": utcnow_iso(), "reason": reason, "sha256": current_digest,
                     "added": added[:200], "flipped": flipped[:200],
                     "countersign": countersign or None,
                     "countersign_verified": False}
            log.append(entry)
            bl["log"] = log
            try:
                baseline_path.write_text(json.dumps(bl, indent=2))
                logged_shas.add(current_digest)
            except OSError as exc:
                # The delta could not be recorded, so it stays UNLOGGED — never silently accepted.
                log = [e for e in log if e is not entry]
                logged_shas.discard(current_digest)
                reason = f"{reason} (NOT RECORDED: {type(exc).__name__}: {exc})"

        unlogged = []
        if current_digest != base_digest and current_digest not in logged_shas:
            unlogged.append({
                "at": utcnow_iso(),
                "summary": (f"specification differs from spec-v0 ({base_digest[:12]} -> "
                            f"{current_digest[:12]}) and from every recorded edit: "
                            f"{len(added)} line(s) added, {len(flipped)} result line(s) changed"),
            })

        # --- outcome flips: one entry per flipped result line, with its approval state ---------
        signed_at = None
        for e in log:
            if e.get("flipped") and (e.get("countersign") or "").strip():
                signed_at = e.get("at") or signed_at
        flips = []
        for line in flipped[:200]:
            flips.append({
                "at": signed_at or utcnow_iso(),
                "summary": line[:300],
                "countersigned": bool(signed_at),
            })

        payload = {
            "sealed": True,
            "specPath": rel_spec,
            "baselineDigest": base_digest,
            "currentDigest": current_digest,
            "driftLogged": not unlogged,
            "unloggedDeltas": unlogged,
            "outcomeFlips": flips,
            "loggedEdits": [{"at": str(e.get("at") or ""), "reason": str(e.get("reason") or ""),
                             "countersigned": bool((e.get("countersign") or "").strip())}
                            for e in log],
            "addedLineCount": len(added),
        }
        note = (f"spec-v0 {base_digest[:12]} vs current {current_digest[:12]}: "
                f"{len(unlogged)} unlogged delta(s), {len(flips)} outcome flip(s), "
                f"{len(log)} recorded edit(s)")
        return self.collected(ctx, payload, note=note)
