"""REQUIREMENTS collector — Phase A2, mechanised as far as it honestly can be.

WHAT PHASE A2 IS. Read the BRD, the HLD, the design system and the wireframes, and turn them
into numbered, risk-ranked conditions the gate can then evidence. It is judgement: no program
can tell whether you read a document *well*.

WHAT IS STILL MECHANICAL, AND IS THE POINT. Whether the reading left a trace that hangs
together. Three properties, none of which grades depth and all of which catch a phase that
did not happen:

  ARTIFACT-FORCING. A2 must emit a manifest. Each requirement carries an id, the source it
  came from with a location inside that source, and at least one link to something the gate
  will actually exercise — a probe id, a CUJ id, a ledger capability. An empty manifest, a
  manifest of prose with no ids, or a manifest whose requirements cite nothing is not a
  requirements pass.

  LINKAGE. Every link must RESOLVE. A requirement pointing at `cuj-checkout` when no such CUJ
  is declared, or at `GET /api/orders` when the ledger has no such capability, is a
  requirement nobody will ever check — which is the same as not having written it, except it
  looks like work. Resolution is against the artifacts the other collectors already wrote
  (`cujs.json`, `probe.json`, `ledger.json`), so it costs nothing extra and cannot be
  satisfied by a claim.

  UNDER-EXTRACTION. If a requirements document is present in the tree and NO requirement
  cites it, that document was not read. This is the cross-check that makes the other two hard
  to game: a manifest of three well-formed, well-linked requirements over a 40-page BRD and a
  design system is exactly what a skipped A2 looks like when somebody writes a manifest
  anyway.

WHAT IS NOT CHECKED, and will not be: whether the requirements are the RIGHT ones, whether
the risk ranking is sensible, whether a condition is testable in principle. That is judgement
and it stays in the self-attested coverage block.

FAIL-FIRST ADMISSION. Same rule as the adversarial probe, for the same reason. Before this
collector reads your repository it runs its own logic over an in-memory CORRECT manifest,
which it must leave clean, and a SEEDED one carrying each of the three defects, every one of
which it must flag. A checker that passes everything and a checker that fails everything are
equally useless; failing either direction makes the evidence ERROR and the gate fails closed.
"""
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..models.evidence import EvidenceKind
from .base import Collector

#: Filenames that are requirements documents. Matched case-insensitively against the name and
#: the immediate parent, so `docs/BRD.md` and `design-system/tokens.md` both count.
#:
#: The list is deliberately narrow. A broad one would sweep in every README in the tree and
#: turn the under-extraction check into noise nobody reads, which is how a useful check dies.
DOCUMENT_PATTERNS = (
    re.compile(r"(?i)\b(brd|business[-_ ]?requirements?)\b"),
    re.compile(r"(?i)\b(hld|lld|high[-_ ]?level[-_ ]?design|solution[-_ ]?design)\b"),
    re.compile(r"(?i)\b(design[-_ ]?system|design[-_ ]?tokens?|style[-_ ]?guide)\b"),
    re.compile(r"(?i)\b(wireframes?|mockups?|prototypes?)\b"),
    re.compile(r"(?i)\b(prd|product[-_ ]?requirements?|functional[-_ ]?spec)\b"),
    re.compile(r"(?i)\b(acceptance[-_ ]?criteria|user[-_ ]?stories)\b"),
)

#: Extensions a requirements document plausibly has. A `.png` wireframe is a real source and
#: is counted; the manifest cites it by path, not by quoting it.
DOCUMENT_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".pdf", ".docx", ".png", ".jpg",
                     ".jpeg", ".svg", ".fig", ".sketch", ".yaml", ".yml", ".json", ".csv")

#: Directories never searched for requirements documents.
SKIP_DIRS = frozenset({".git", "node_modules", "shipgate-workdir", "__pycache__", ".venv",
                       "venv", "dist", "build", "vendor", "target", ".next", "coverage"})

#: Risk levels a requirement may declare. Free text is refused rather than ranked, because a
#: ranking nobody can compare is not a ranking.
RISK_LEVELS = ("critical", "high", "medium", "low")

MAX_DEPTH = 6
MAX_DOCS = 200


class RequirementsError(ValueError):
    """The manifest cannot be read. Always ERROR evidence, never a silent skip."""


# =======================================================================================
# the three checks — pure functions over (manifest, known_ids, documents)
# =======================================================================================


def evaluate_manifest(manifest, known, documents) -> Dict[str, Any]:
    """The whole of A2's mechanical judgement.

    `known` is {"cujs": {...}, "capabilities": {...}, "routes": {...}} — ids the rest of the
    run will actually exercise. `documents` is the requirement documents present in the tree.
    Pure, so the admission check below can drive it with in-memory inputs.
    """
    requirements = manifest.get("requirements")
    findings: List[Dict[str, str]] = []
    if not isinstance(requirements, list) or not requirements:
        return {"requirements": [], "findings": [{
            "kind": "empty_manifest", "id": "-",
            "detail": "the manifest declares no requirements; an A2 pass that extracted "
                      "nothing is not an A2 pass"}],
            "cited": [], "uncited": sorted(documents), "counts": _counts([], 1)}

    seen_ids, rows, cited = set(), [], set()
    for index, raw in enumerate(requirements):
        row, problems = _one(raw, index, known)
        rows.append(row)
        if row["id"] in seen_ids:
            problems.append(("duplicate_id",
                             f"requirement id {row['id']!r} is used more than once"))
        seen_ids.add(row["id"])
        cited.update(row["sources"])
        for kind, detail in problems:
            findings.append({"kind": kind, "id": row["id"], "detail": detail})

    # UNDER-EXTRACTION. Matched on the tail of the path so a manifest may cite
    # `docs/design-system.md` or the absolute path and both resolve.
    uncited = sorted(d for d in documents if not any(_same_doc(d, c) for c in cited))
    for doc in uncited:
        findings.append({
            "kind": "document_not_cited", "id": doc,
            "detail": f"{doc} is a requirements document in this tree and no requirement "
                      f"cites it; a source nothing was extracted from was not read"})

    return {"requirements": rows, "findings": findings,
            "cited": sorted(cited), "uncited": uncited,
            "counts": _counts(rows, len(findings))}


def _one(raw, index, known) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
    problems: List[Tuple[str, str]] = []
    if not isinstance(raw, dict):
        return ({"id": f"#{index}", "sources": [], "links": [], "risk": "", "text": ""},
                [("malformed_requirement",
                  f"entry {index} is {type(raw).__name__}, expected an object")])
    rid = str(raw.get("id") or "").strip() or f"#{index}"
    text = str(raw.get("text") or raw.get("condition") or "").strip()
    risk = str(raw.get("risk") or "").strip().lower()

    if not text:
        problems.append(("no_condition",
                         "the requirement states no condition; an id with no sentence "
                         "behind it cannot be evidenced or refuted"))
    if risk not in RISK_LEVELS:
        problems.append(("unranked",
                         f"risk is {risk or 'absent'!r}; A2 requires a comparable ranking "
                         f"from {', '.join(RISK_LEVELS)}"))

    sources, links = [], []
    for src in _as_list(raw.get("source")) + _as_list(raw.get("sources")):
        if isinstance(src, str):
            sources.append(src.strip())
        elif isinstance(src, dict) and src.get("document"):
            doc = str(src["document"]).strip()
            where = str(src.get("at") or src.get("location") or "").strip()
            if not where:
                problems.append(("no_source_span",
                                 f"cites {doc} with no location inside it; a citation "
                                 f"without a span cannot be checked by a reader"))
            sources.append(doc)
    if not sources:
        problems.append(("no_source",
                         "no source document is cited, so this requirement came from "
                         "nowhere the gate can point at"))

    for link in _as_list(raw.get("evidence")) + _as_list(raw.get("links")):
        ref = str(link).strip()
        if not ref:
            continue
        links.append(ref)
        if not _resolves(ref, known):
            problems.append(("dangling_link",
                             f"links to {ref!r}, which is not a declared CUJ, a probed route "
                             f"or a ledger capability; nothing will ever exercise it"))
    if not links:
        problems.append(("unlinked",
                         "links to no CUJ, route or capability, so no evidence in this run "
                         "bears on it"))
    return ({"id": rid, "sources": sources, "links": links, "risk": risk,
             "text": text[:300]}, problems)


def _resolves(ref, known):
    if ref in known.get("cujs", ()) or ref in known.get("capabilities", ()):
        return True
    if ref in known.get("routes", ()):
        return True
    # `GET /api/orders` and `/api/orders` both resolve against a probed route.
    tail = ref.split(None, 1)[-1] if " " in ref else ref
    return tail in known.get("routes", ())


def _same_doc(document, citation):
    d = str(document).replace("\\", "/").lstrip("./").lower()
    c = str(citation).replace("\\", "/").lstrip("./").lower()
    return d == c or d.endswith("/" + c) or c.endswith("/" + d)


def _as_list(v):
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _counts(rows, findings):
    by_risk = {level: 0 for level in RISK_LEVELS}
    for r in rows:
        if r["risk"] in by_risk:
            by_risk[r["risk"]] += 1
    return {"requirements": len(rows), "findings": findings,
            "linked": sum(1 for r in rows if r["links"]),
            "byRisk": by_risk}


# =======================================================================================
# fail-first admission
# =======================================================================================

_REF_KNOWN = {"cujs": {"cuj-checkout", "cuj-login"},
              "capabilities": {"route:GET:/api/orders"},
              "routes": {"/api/orders", "/health"}}
_REF_DOCS = ["docs/BRD.md", "docs/design-system.md"]

_REF_GOOD = {"requirements": [
    {"id": "R-1", "text": "A signed-in user can complete checkout.", "risk": "critical",
     "source": [{"document": "docs/BRD.md", "at": "§3.2"}], "evidence": ["cuj-checkout"]},
    {"id": "R-2", "text": "Order list is served.", "risk": "high",
     "source": [{"document": "docs/BRD.md", "at": "§4.1"}], "evidence": ["GET /api/orders"]},
    {"id": "R-3", "text": "Primary buttons use the brand palette.", "risk": "medium",
     "source": [{"document": "docs/design-system.md", "at": "tokens/colour"}],
     "evidence": ["/health"]},
]}

#: Each entry carries exactly one defect, so a partial checker cannot pass by catching a
#: different one. Every `kind` here must appear in the seeded run's findings.
_REF_SEEDED = {"requirements": [
    {"id": "R-1", "text": "A signed-in user can complete checkout.", "risk": "critical",
     "source": [{"document": "docs/BRD.md", "at": "§3.2"}],
     "evidence": ["cuj-nonexistent"]},                                    # dangling_link
    {"id": "R-2", "text": "Order list is served.", "risk": "high",
     "source": [{"document": "docs/BRD.md"}],                             # no_source_span
     "evidence": ["GET /api/orders"]},
    {"id": "R-3", "text": "Something vague.", "risk": "",                 # unranked
     "source": [{"document": "docs/BRD.md", "at": "§9"}], "evidence": ["/health"]},
    {"id": "R-4", "text": "", "risk": "low",                              # no_condition
     "source": [{"document": "docs/BRD.md", "at": "§9"}], "evidence": ["/health"]},
    {"id": "R-5", "text": "Unlinked condition.", "risk": "low",
     "source": [{"document": "docs/BRD.md", "at": "§9"}], "evidence": []},  # unlinked
    {"id": "R-1", "text": "Duplicate.", "risk": "low",                    # duplicate_id
     "source": [{"document": "docs/BRD.md", "at": "§9"}], "evidence": ["/health"]},
]}                                     # ...and docs/design-system.md: document_not_cited

_MUST_CATCH = ("dangling_link", "no_source_span", "unranked", "no_condition", "unlinked",
               "duplicate_id", "document_not_cited")


def admission() -> Dict[str, Any]:
    """Prove the checker works before it reads anything of yours. Never raises."""
    clean = evaluate_manifest(_REF_GOOD, _REF_KNOWN, _REF_DOCS)
    seeded = evaluate_manifest(_REF_SEEDED, _REF_KNOWN, _REF_DOCS)
    caught = sorted({f["kind"] for f in seeded["findings"]})
    missed = [k for k in _MUST_CATCH if k not in caught]
    false_alarms = [f"{f['kind']}:{f['id']}" for f in clean["findings"]]
    admitted = not missed and not false_alarms
    return {
        "admitted": admitted,
        "defectClasses": list(_MUST_CATCH),
        "caught": caught,
        "missed": missed,
        "falseAlarmsOnCorrectManifest": false_alarms,
        "detail": ("every seeded defect class was caught on the reference manifest and none "
                   "fired on the correct one"
                   if admitted else
                   "; ".join(filter(None, [
                       f"MISSED {', '.join(missed)}" if missed else "",
                       f"{len(false_alarms)} false alarm(s) on the correct manifest: "
                       f"{false_alarms[:4]}" if false_alarms else ""]))),
    }


# =======================================================================================
# the collector
# =======================================================================================


class RequirementsCollector(Collector):
    """Phase A2's artifact, checked for structure, linkage and under-extraction.

    Options: `requirements_file` (default `<workdir>/requirements.json`),
    `requirement_documents` (an explicit list, overriding discovery).
    """

    kind = EvidenceKind.REQUIREMENTS
    name = "requirements"
    version = "4.2.2"

    def collect(self, ctx):
        adm = admission()
        if not adm["admitted"]:
            return self.error(
                ctx, "the requirements checker FAILED its own fail-first admission and was "
                     f"not run against this repository: {adm['detail']}",
                payload={"admission": adm})

        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        path = Path(ctx.option("requirements_file") or (workdir / "requirements.json"))

        documents = self._documents(ctx, root)
        if not path.exists():
            # ABSENT, not ERROR and not an empty pass. The gate cannot write your
            # requirements. The omission is published as a Phase A2 coverage caveat rather
            # than swallowed — see models/coverage.py.
            return self.absent(
                ctx,
                f"no requirements manifest at {path.name}; Phase A2 coverage stays "
                f"UNCOLLECTED. Template: assets/templates/requirements.json.template. "
                + (f"{len(documents)} requirements document(s) are present in this tree and "
                   f"nothing has been extracted from them."
                   if documents else
                   "No requirements document was found in this tree either."))
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return self.error(ctx, f"requirements manifest {path.name} is unreadable "
                                   f"({type(exc).__name__}: {exc}); a manifest that cannot be "
                                   f"read is not a manifest")
        if not isinstance(manifest, dict):
            return self.error(ctx, f"{path.name} is not an object")

        known = self._known(workdir)
        result = evaluate_manifest(manifest, known, documents)
        payload = {
            "admission": adm,
            "manifestPath": str(path.relative_to(root)) if _under(path, root) else str(path),
            "documentsPresent": documents,
            "documentsCited": result["cited"],
            "documentsUncited": result["uncited"],
            "knownIds": {k: sorted(v)[:60] for k, v in known.items()},
            "requirements": result["requirements"],
            "findings": result["findings"],
            "counts": result["counts"],
        }
        uncovered = []
        if not any(known.values()):
            uncovered.append(
                "no CUJ, probe or ledger artifact was available to resolve links against, so "
                "linkage was not established for any requirement")
        note = (f"{result['counts']['requirements']} requirement(s), "
                f"{result['counts']['linked']} linked, "
                f"{len(result['findings'])} finding(s); "
                f"{len(documents) - len(result['uncited'])}/{len(documents)} document(s) cited")
        return self.collected(ctx, payload, note=note, uncovered=tuple(uncovered))

    # -- inputs -------------------------------------------------------------------------
    def _documents(self, ctx, root) -> List[str]:
        explicit = ctx.option("requirement_documents")
        if isinstance(explicit, list):
            return sorted(str(d) for d in explicit)
        found = []
        for dirpath, dirnames, filenames in os.walk(root):
            depth = len(Path(dirpath).relative_to(root).parts)
            if depth >= MAX_DEPTH:
                dirnames[:] = []
                continue
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in SKIP_DIRS and not d.startswith("."))
            for name in sorted(filenames):
                if not name.lower().endswith(DOCUMENT_SUFFIXES):
                    continue
                rel = str(Path(dirpath, name).relative_to(root)).replace(os.sep, "/")
                hay = rel.replace("_", "-")
                if any(p.search(hay) for p in DOCUMENT_PATTERNS):
                    found.append(rel)
                    if len(found) >= MAX_DOCS:
                        return sorted(found)
        return sorted(found)

    def _known(self, workdir) -> Dict[str, set]:
        """Ids the rest of this run will actually exercise, read from what other collectors
        already wrote. Nothing here is supplied by the manifest's author."""
        known = {"cujs": set(), "capabilities": set(), "routes": set()}
        for name, key, extract in (
                ("cujs.json", "cujs", _cuj_ids),
                ("ledger.json", "capabilities", _ledger_ids),
                ("probe.json", "routes", _probe_paths)):
            try:
                doc = json.loads((workdir / name).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            try:
                known[key].update(extract(doc))
            except Exception:  # noqa: BLE001 — a malformed artifact resolves nothing
                continue
        return known


def _cuj_ids(doc):
    rows = doc.get("journeys") if isinstance(doc, dict) else doc
    return [str(r.get("id")) for r in (rows or []) if isinstance(r, dict) and r.get("id")]


def _ledger_ids(doc):
    rows = doc.get("entries") if isinstance(doc, dict) else doc
    return [str(r.get("id")) for r in (rows or []) if isinstance(r, dict) and r.get("id")]


def _probe_paths(doc):
    out = []
    for r in (doc.get("routes") if isinstance(doc, dict) else doc) or []:
        if isinstance(r, dict) and r.get("path"):
            out.append(str(r["path"]))
            if r.get("method"):
                out.append(f"{r['method']} {r['path']}")
    return out


def _under(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def describe() -> str:
    return "\n".join([
        "REQUIREMENTS — the mechanical floor of Phase A2.",
        "",
        "  Checked: every requirement has an id, a stated condition, a comparable risk rank,",
        "  a source document WITH a location inside it, and at least one link that RESOLVES",
        "  to a declared CUJ, a probed route or a ledger capability. Plus under-extraction:",
        "  a requirements document present in the tree that no requirement cites.",
        "",
        f"  Defect classes, all seeded and caught before the collector runs: "
        f"{', '.join(_MUST_CATCH)}.",
        "",
        "  NOT checked, and still Phase A2's job: whether these are the RIGHT requirements,",
        "  whether the risk ranking is sensible, whether a condition is worth testing. That",
        "  is judgement and it stays self-attested — see models/coverage.py.",
    ])
