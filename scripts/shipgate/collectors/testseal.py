"""TEST_SEAL collector — the visible test suite, checksummed and anchored.

Ported from v3.8 `vault.py` (`seal` / `check` / `seal_delta` / `merge_baseline` /
`_anchor_baseline`). Everything that made the v3.8 seal hard to launder is preserved:

  * every visible test file AND test config is checksummed;
  * `seal_delta` still distinguishes the ordinary flow (ADDING a test) from the move the
    seal exists to catch (MODIFYING or DELETING an already-sealed one);
  * the append-only `reseal_log` still accumulates across seals, so re-sealing a second time
    cannot erase the record that an edit happened;
  * the BASELINE is anchored OUTSIDE the vault, in `<workdir>/state.json`, and is append-only:
    `rm -rf .vault` followed by a fresh seal cannot mint a new anchor over gutted tests, and a
    regression test added in a later round is anchored at its first-sealed hash rather than
    sitting outside the anchor's scope forever;
  * the seal is dated (`sealedAt`) and carries the round it was written in.

Three v3.8 defects are closed here, each marked FIX-:

  FIX-SEAL-EMPTY-IS-REPORTED   v3.8 could be talked into a zero-file seal with
                               `--allow-empty "<reason>"`, and a zero-file seal satisfies the
                               artifact requirement while protecting nothing. There is no
                               allow-empty here: `fileCount` is reported honestly and
                               `test_seal_intact` turns 0 into SEM_TEST_SEAL_EMPTY.
  FIX-SEAL-COVERS-COMMAND      the seal must cover the TEST COMMAND DEFINITION, not just the
                               spec files, or swapping `"test": "vitest run"` for
                               `"test": "true"` destroys the oracle without touching a sealed
                               file. v3.8 covered `package.json` only; this covers
                               pyproject/tox/pytest.ini/setup.cfg/noxfile/Makefile/*.csproj
                               too, and `coveredCommandDefinition` states whether a file that
                               genuinely DEFINES a test command is inside the seal.
  FIX-SEAL-DELETION-DETECTED   de-sealing by DELETION is reported in its own `deletions` list
                               rather than being folded into a generic "changed" bucket.

Filesystem reads and writes inside the run area only; no process is spawned.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from ..util.clock import utcnow_iso
from ..util.hashing import sha256_file
from .base import Collector

SEAL_VERSION = 3

#: v3.8 TEST_GLOBS, unchanged, plus the command-definition files (FIX-SEAL-COVERS-COMMAND).
TEST_GLOBS = [
    "**/*.spec.*", "**/*.test.*", "**/test_*.py", "**/tests/**/*.py",
    "**/playwright.config.*", "**/jest.config.*", "**/vitest.config.*",
    "**/pytest.ini", "**/stryker.config.*", "**/conftest.py",
    "**/package.json",
]
# FIX-SEAL-COMMAND-PORTABILITY: only the JS / Python / .NET command-definition files were
# recognised, so on a Gradle, Maven, Cargo or Go repository `coveredCommandDefinition` was
# False and the seal check FAILED for a reason that had nothing to do with the repository's
# integrity — a portability defect on stacks the gate claims to support. Those ecosystems
# are recognised now; anything still unrecognised remains an honest False.
COMMAND_GLOBS = [
    "**/package.json", "**/pyproject.toml", "**/tox.ini", "**/pytest.ini", "**/setup.cfg",
    "**/noxfile.py", "**/Makefile", "**/makefile", "**/GNUmakefile", "**/*.csproj",
    "**/build.gradle", "**/build.gradle.kts", "**/settings.gradle",
    "**/settings.gradle.kts", "**/pom.xml", "**/Cargo.toml", "**/go.mod",
    "**/justfile", "**/Justfile", "**/Taskfile.yml", "**/Taskfile.yaml",
]
SKIP = {"node_modules", ".git", "shipgate-workdir", ".vault", "dist", "build", ".next",
        "venv", ".venv", "__pycache__", "coverage"}

_MAKE_TEST = re.compile(r"(?m)^(test|tests|check|unit|integration)\s*:")
_JUST_TEST = re.compile(r"(?m)^(test|tests|check)[\w\- ]*:")
_GRADLE_TEST = re.compile(
    r"(?s)\btest\s*[({]|\btasks\.(named\(\s*['\"]test|test\b)|useJUnitPlatform")
_MAVEN_TEST = re.compile(
    r"(?s)<artifactId>\s*maven-(surefire|failsafe)-plugin|<scope>\s*test\s*</scope>")
_PYPROJECT_TEST = re.compile(
    r"(?m)^\s*\[tool\.(pytest|tox|nox|hatch\.envs\.[\w.-]+\.scripts)|^\s*test\s*=")


def _rel(root, p):
    return p.relative_to(root).as_posix()


def _visible_tests(root):
    """v3.8 `visible_tests`, plus the command-definition globs. Deterministic order."""
    seen = {}
    for g in TEST_GLOBS + COMMAND_GLOBS:
        for f in Path(root).glob(g):
            if not f.is_file():
                continue
            try:
                rel = _rel(root, f)
            except ValueError:
                continue
            if set(Path(rel).parts) & SKIP:
                continue
            seen[rel] = f
    return dict(sorted(seen.items()))


def _read(p):
    try:
        return Path(p).read_text(errors="ignore")
    except OSError:
        return ""


def defines_test_command(rel, path):
    """True iff this file DEFINES how the suite is run — the oracle, not just the tests.

    A seal that covers every spec file but not the script that runs them protects the tests
    and not the oracle: `"test": "true"` guts the suite without touching a sealed spec.
    """
    name = Path(rel).name
    text = _read(path)
    if not text:
        return False
    if name == "package.json":
        try:
            doc = json.loads(text)
        except Exception:  # noqa: BLE001 — malformed manifest defines nothing we can rely on
            return False
        scripts = doc.get("scripts") if isinstance(doc, dict) else None
        return bool(isinstance(scripts, dict) and str(scripts.get("test") or "").strip())
    if name == "pyproject.toml":
        return bool(_PYPROJECT_TEST.search(text))
    if name == "tox.ini":
        return "[testenv" in text
    if name == "pytest.ini":
        return "[pytest]" in text
    if name == "setup.cfg":
        return "[tool:pytest]" in text
    if name == "noxfile.py":
        return "@nox.session" in text
    if name in ("Makefile", "makefile", "GNUmakefile"):
        return bool(_MAKE_TEST.search(text))
    if name.endswith(".csproj"):
        low = text.lower()
        return "microsoft.net.test.sdk" in low or "<istestproject>true" in low
    # FIX-SEAL-COMMAND-PORTABILITY (continued).
    if name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        return bool(_GRADLE_TEST.search(text))
    if name == "pom.xml":
        return bool(_MAVEN_TEST.search(text))
    if name == "Cargo.toml":
        # `cargo test` IS the command; the manifest is what defines the test targets and the
        # dev-dependency set the suite compiles against.
        return "[package]" in text or "[[test]]" in text or "[dev-dependencies]" in text
    if name == "go.mod":
        # `go test ./...` is defined by the module declaration.
        return bool(re.search(r"(?m)^module\s+\S+", text))
    if name in ("justfile", "Justfile"):
        return bool(_JUST_TEST.search(text))
    if name in ("Taskfile.yml", "Taskfile.yaml"):
        return bool(re.search(r"(?m)^\s{2,}(test|tests|check)\s*:", text))
    return False


def _load_json(path):
    try:
        doc = json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None
    return doc if isinstance(doc, dict) else None


def merge_baseline(existing, doc):
    """v3.8 `merge_baseline`, verbatim in behaviour: APPEND-ONLY.

    New files are anchored at their first-sealed hash; an already-anchored entry is never
    rewritten, and a REMOVAL is never applied — a file dropping out of the seal must stay
    anchored, or deleting a test would erase the evidence that it ever existed.
    """
    if not (isinstance(existing, dict) and isinstance(existing.get("files"), dict)):
        return ({"sealed_at": doc["sealed_at"], "round": doc["round"],
                 "file_count": doc["file_count"], "files": dict(doc["files"])},
                sorted(doc["files"]))
    files = dict(existing["files"])
    added = sorted(k for k in doc["files"] if k not in files)
    for k in added:
        files[k] = doc["files"][k]
    out = dict(existing)
    out["files"] = files
    out["file_count"] = len(files)
    return out, added


def seal_delta(previous_files, sums):
    """v3.8 `seal_delta`: what this seal changes relative to the seal it replaces."""
    if not isinstance(previous_files, dict):
        return None
    return {
        "modified": sorted(k for k in previous_files if k in sums and sums[k] != previous_files[k]),
        "removed": sorted(k for k in previous_files if k not in sums),
        "added": sorted(k for k in sums if k not in previous_files),
    }


class TestSealCollector(Collector):
    """Seal the visible test suite and report every deviation from the anchored baseline.

    Options: `vault` (default `<workdir>/.vault`), `state_file`
    (default `<workdir>/state.json`), `reseal_reason` (an admitted Test Author change).
    """

    kind = EvidenceKind.TEST_SEAL
    name = "test-seal"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        vault = Path(ctx.option("vault") or (workdir / ".vault"))
        state_file = Path(ctx.option("state_file") or (workdir / "state.json"))
        rnd = int(getattr(ctx.binding, "round_index", 0) or 0)
        reseal_reason = (ctx.option("reseal_reason") or "").strip() or None

        found = _visible_tests(root)
        sums, unreadable = {}, []
        command_files = []
        for rel, path in found.items():
            try:
                sums[rel] = sha256_file(path)
            except OSError as exc:
                unreadable.append(f"{rel}: {type(exc).__name__}")
                continue
            if defines_test_command(rel, path):
                command_files.append(rel)

        violations = list(f"unreadable test file, so it cannot be sealed: {u}" for u in unreadable)

        # --- the anchor: append-only, OUTSIDE the vault ---------------------------------------
        state = _load_json(state_file) or {}
        anchor = state.get("seal_baseline")
        anchored = anchor.get("files") if isinstance(anchor, dict) else None
        anchored = anchored if isinstance(anchored, dict) else {}

        prev_seal = _load_json(vault / "seal.json") or {}
        prev_files = prev_seal.get("files") if isinstance(prev_seal.get("files"), dict) else {}
        reseal_log = list(prev_seal.get("reseal_log") or [])

        # Files whose modification/removal has ALREADY been adjudicated with a recorded reason
        # stay recorded but do not re-break the seal on every later round.
        #
        # `adjudicated` is the v4.0 field and is authoritative. The `modified`/`removed` clause
        # below reads seals written by the older shape, where the excused set had to be inferred
        # from a delta that happened to carry a reason. Both are honoured so an existing vault
        # keeps working; new entries always write `adjudicated` explicitly.
        excused = set()
        for entry in reseal_log:
            if not isinstance(entry, dict):
                continue
            for k in list(entry.get("adjudicated") or []):
                if isinstance(k, str):
                    excused.add(k)
            if (entry.get("reason") or "").strip():
                for k in list(entry.get("modified") or []) + list(entry.get("removed") or []):
                    if isinstance(k, str):
                        excused.add(k)

        # --- deviations vs the anchor (the laundering-proof comparison) -----------------------
        deletions, modifications = [], []
        for k, h in sorted(anchored.items()):
            if k not in sums:
                deletions.append(k)          # FIX-SEAL-DELETION-DETECTED
            elif sums[k] != h:
                modifications.append(k)
        # ...and vs the seal this run replaces (v3.8 `check`).
        for k, h in sorted(prev_files.items()):
            if k not in sums and k not in deletions:
                deletions.append(k)
            elif k in sums and sums[k] != h and k not in modifications:
                modifications.append(k)

        known = set(anchored) | set(prev_files)
        additions = sorted(k for k in sums if k not in known)

        # FIX-SEAL-RESEAL-REASON-OFF-BY-ONE.
        #
        # The reason used to take effect one round LATE. `excused` was built from the PREVIOUS
        # seal's log, so the round on which the Test Author actually supplied the admission
        # still failed, and the next round — which supplied nothing — passed. The operator was
        # being asked to explain a change on one round and being punished for it on that round.
        # Worse, a file modified with no reason could never be adjudicated afterwards: by the
        # next round the delta against the previous seal was empty, so no log entry carrying a
        # reason was ever written and the deviation against the ANCHOR stayed unexcused
        # forever. A gate that cannot be answered is not a gate, it is a dead end.
        #
        # A reason now adjudicates the deviations that are OUTSTANDING AT THIS MOMENT — every
        # detected deletion or modification not already excused — and does it before the
        # violations are built, so the admission lands on the round that made it. Nothing is
        # loosened: the deviations are still detected against the append-only anchor, still
        # listed in `deletions`/`additions`, and the adjudication itself is written into the
        # append-only `reseal_log` with the round, the timestamp and the exact file list. What
        # changes is only WHEN a recorded admission takes effect.
        pending = sorted((set(deletions) | set(modifications)) - excused)
        adjudicated = pending if (reseal_reason and pending) else []
        excused.update(adjudicated)

        for k in sorted(set(deletions)):
            if k in excused:
                continue
            violations.append(
                f"deleted since it was sealed: {k} — de-sealing by deletion removes the oracle "
                f"without editing a sealed byte")
        for k in sorted(set(modifications)):
            if k in excused:
                continue
            violations.append(f"modified since it was sealed: {k}")

        # --- the command definition must be inside the seal -----------------------------------
        covered_command = bool(command_files)
        if not covered_command:
            violations.append(
                "no test command definition (package.json \"scripts.test\", pyproject/tox/"
                "pytest.ini/setup.cfg/noxfile/Makefile test target, or a test .csproj) was found "
                "and sealed, so the command that runs the suite could be gutted without breaking "
                "the seal")

        # --- write the seal, the vault baseline and the external anchor -------------------------
        sealed_at = utcnow_iso()
        delta = seal_delta(prev_files, sums)
        touched = sorted(set((delta or {}).get("modified", []) + (delta or {}).get("removed", [])))
        doc = {
            "seal_version": SEAL_VERSION,
            "sealed_at": sealed_at,
            "round": rnd,
            "state_file": str(state_file),
            "file_count": len(sums),
            "reseal_reason": reseal_reason,
            "resealed_over": delta,
            "files": sums,
        }
        if touched or adjudicated:
            # APPEND-ONLY: a later seal can never erase an earlier delta.
            #
            # Two different facts share one entry, and they are not the same fact. `modified`
            # and `removed` are what changed since the seal this run replaces — the factual
            # record, written whether or not anybody explained it. `adjudicated` is what this
            # round's reason excused, which may be wider: it can cover a deviation against the
            # anchor that an earlier round left unexplained. Recording them separately is what
            # keeps "something changed" readable apart from "somebody signed for it".
            reseal_log.append({"at": sealed_at, "round": rnd, "reason": reseal_reason,
                               "modified": (delta or {}).get("modified", []),
                               "removed": (delta or {}).get("removed", []),
                               "adjudicated": adjudicated})
        doc["reseal_log"] = reseal_log

        write_errors = []
        try:
            vault.mkdir(parents=True, exist_ok=True)
            (vault / "seal.json").write_text(json.dumps(doc, indent=2))
            merged_vault, _ = merge_baseline(_load_json(vault / "seal-baseline.json"), doc)
            merged_vault["baseline"] = True
            (vault / "seal-baseline.json").write_text(json.dumps(merged_vault, indent=2))
        except OSError as exc:
            write_errors.append(f"vault: {type(exc).__name__}: {exc}")
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            merged_anchor, _ = merge_baseline(anchor, doc)
            state["seal_baseline"] = merged_anchor
            state_file.write_text(json.dumps(state, indent=2))
        except OSError as exc:
            write_errors.append(f"anchor: {type(exc).__name__}: {exc}")
        for e in write_errors:
            violations.append(
                f"the seal could not be persisted ({e}); an unpersisted seal protects nothing")

        payload = {
            "intact": not violations,
            "fileCount": len(sums),                       # FIX-SEAL-EMPTY-IS-REPORTED
            "coveredCommandDefinition": covered_command,  # FIX-SEAL-COVERS-COMMAND
            "violations": violations,
            "sealedAt": sealed_at,
            "round": rnd,
            "files": [{"path": k, "sha256": v} for k, v in sorted(sums.items())],
            "deletions": sorted(set(deletions)),          # FIX-SEAL-DELETION-DETECTED
            "additions": additions,
            "commandDefinitions": sorted(command_files),
            "anchoredFileCount": len(anchored),
            "resealExcused": sorted(excused),
            "resealAdjudicatedThisRound": adjudicated,   # FIX-SEAL-RESEAL-REASON-OFF-BY-ONE
        }
        note = (f"sealed {len(sums)} file(s) at round {rnd}; "
                f"{len(violations)} violation(s); command definition "
                f"{'covered' if covered_command else 'NOT covered'}"
                + (f"; {len(adjudicated)} deviation(s) adjudicated this round by the supplied "
                   f"reseal_reason" if adjudicated else ""))
        return self.collected(ctx, payload, note=note)
