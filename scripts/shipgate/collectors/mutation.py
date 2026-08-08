"""MUTATION collector — can the suite detect injected bugs at scale?

Ported from v3.8 `mutation.py`, keeping the parts that made its number trustworthy:

  * TOOL DETECTION per stack — StrykerJS (JS/TS), Stryker.NET (C#/.NET), mutmut and
    cosmic-ray (Python) — and the PINNED-LOCAL rule: the Stryker binary is taken from the run
    area's `node_modules/.bin`, never `npx --yes`, which fetches LATEST at call time;
  * STALE-REPORT REJECTION: report mtimes are recorded BEFORE the run, and only a report that
    is new or newer AND a successful exit are accepted. A failed Stryker run must never be
    scored from a leftover `mutation-report.json`;
  * the full Stryker report parser (Killed/Timeout/Survived/NoCoverage per mutant, shared by
    StrykerJS and Stryker.NET, which emit the same schema) so the DISTRIBUTION is recorded and
    not just the aggregate — a bare score hides gaming-by-scope (100% of 3 mutants in 1 file);
  * `scope` is recorded, so a diff-scoped incremental run can never be mistaken for the
    whole-repo run the threshold is written against.

FIX-MUTATION-NO-SILENT-ZERO: v3.8's `js()`/`py()`/`cs()` returned None when the tool was
missing, unconfigured or unparseable, and the caller wrote a mutation.json with no score —
which downstream read as "no evidence" in some places and as 0 in others. Here an
unmeasurable mutation score is ERROR evidence with the reason attached. It is NEVER
`scorePct: 0`, because 0 is a measurement and "we could not measure" is not.

FIX-MUTATION-INT-SCORE: the score is an int (floor) — the canonicaliser rejects floats, and a
platform-dependent `61.99999` in a decision digest is not reproducible.

Every process goes through `ctx.adapter.run_target`; nothing here imports `subprocess`.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127
ERROR_RCS = (RC_TIMEOUT, RC_OUTPUT_LIMIT, RC_SPAWN_FAILED)

SRC_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".py", ".cs"}
REPORT_SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__"}


# FIX-MUTATION-DEFAULT-REPORT-PATH: only `mutation-report.json` was searched for, but
# StrykerJS's json reporter writes `reports/mutation/mutation.json` unless the operator adds a
# `jsonReporter.fileName` override. A SUCCESSFUL Stryker run was therefore recorded as ERROR
# ("produced no fresh, parseable report"), which made the required MUTATION evidence missing
# and raised a showstopper on a repo whose mutation testing had actually worked. Every name a
# supported tool writes by default is now recognised.
REPORT_NAMES = (
    "mutation-report.json",   # Stryker with an explicit jsonReporter.fileName
    "mutation.json",          # StrykerJS default: reports/mutation/mutation.json
    "mutation-report.xml",    # Stryker.NET, when only the xml reporter is enabled
)


def _reports(root):
    """Every recognised mutation report in the run area, with its mtime (0 when unreadable)."""
    out = {}
    for name in REPORT_NAMES:
        for p in Path(root).rglob(name):
            try:
                if set(p.relative_to(root).parts) & REPORT_SKIP:
                    # A report inside node_modules belongs to a dependency, not to this run.
                    continue
                out[str(p)] = p.stat().st_mtime
            except OSError:
                continue
    return out


def parse_stryker_report(path):
    """StrykerJS / Stryker.NET share this schema. Returns the count dict or None."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return None
    counts, total = {}, 0
    for f in files.values():
        for m in (f.get("mutants") or []) if isinstance(f, dict) else []:
            total += 1
            st = str(m.get("status", "?"))
            counts[st] = counts.get(st, 0) + 1
    if not total:
        return None
    killed = counts.get("Killed", 0) + counts.get("Timeout", 0)
    return {
        "total": total,
        "killed": killed,
        "survived": counts.get("Survived", 0),
        "timeout": counts.get("Timeout", 0),
        "noCoverage": counts.get("NoCoverage", 0),
        "files": len(files),
    }


def parse_mutmut(text):
    """v3.8 mutmut parsing: `<killed>/<total> killed`, else count the result words."""
    m = re.search(r"(\d+)\s*/\s*(\d+)\s+killed", text, re.I)
    if m:
        killed, total = int(m.group(1)), int(m.group(2))
        if total:
            return {"total": total, "killed": killed, "survived": max(0, total - killed),
                    "timeout": 0, "noCoverage": 0, "files": 0}
    killed = len(re.findall(r"\bkilled\b", text, re.I))
    survived = len(re.findall(r"\bsurvived\b", text, re.I))
    timeout = len(re.findall(r"\btimeout\b", text, re.I))
    total = killed + survived + timeout
    if total:
        return {"total": total, "killed": killed + timeout, "survived": survived,
                "timeout": timeout, "noCoverage": 0, "files": 0}
    return None


def parse_cosmic_ray(text):
    """`cr-report` prints 'total jobs: N', 'complete: N', 'surviving mutants: N'."""
    total = re.search(r"total jobs:\s*(\d+)", text, re.I)
    surviving = re.search(r"surviving mutants:\s*(\d+)", text, re.I)
    if not (total and surviving):
        return None
    t, s = int(total.group(1)), int(surviving.group(1))
    if not t:
        return None
    return {"total": t, "killed": max(0, t - s), "survived": s, "timeout": 0,
            "noCoverage": 0, "files": 0}


class MutationCollector(Collector):
    """Run the stack's mutation tool and report the killed/survived distribution.

    Options: `mutation_tool` (force one of stryker/stryker-net/mutmut/cosmic-ray),
    `mutation_scope` ("whole-repo" | "changed"), `mutation_ref` (diff base, default HEAD),
    `mutation_timeout` (default 3600).
    """

    kind = EvidenceKind.MUTATION
    name = "mutation"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        timeout = int(ctx.option("mutation_timeout", 3600) or 3600)
        scope = "changed" if str(ctx.option("mutation_scope", "whole-repo")) == "changed" \
            else "whole-repo"

        changed = None
        if scope == "changed":
            changed = self._changed_files(ctx, root)
            if changed is None:
                return self.error(ctx, "changed-file scope was requested but `git diff` could not "
                                       "resolve it; refusing to report a whole-repo score as a "
                                       "changed-scope one, or an empty run as a measurement")
            if not changed:
                # v3.8 recorded this as scope="diff-empty" with NO score. A run that mutated
                # nothing has not measured anything; it must not become a number.
                return self.error(ctx, "no source file changed against the diff base, so nothing "
                                       "was mutated; the previous whole-repo score still governs "
                                       "and this run measured nothing")

        tool = ctx.option("mutation_tool") or self._detect(ctx, root)
        if not tool:
            return self.error(ctx, "no mutation tool is available in the run area (StrykerJS in "
                                   "node_modules/.bin, Stryker.NET via `dotnet stryker`, mutmut or "
                                   "cosmic-ray). This layer cannot be skipped silently")

        runner = {
            "stryker": self._run_stryker,
            "stryker-net": self._run_stryker_net,
            "mutmut": self._run_mutmut,
            "cosmic-ray": self._run_cosmic_ray,
        }.get(tool)
        if runner is None:
            return self.error(ctx, f"unknown mutation tool {tool!r}")

        counts, detail = runner(ctx, root, timeout, changed)
        if counts is None:
            return self.error(ctx, f"{tool}: {detail}")

        total = int(counts["total"])
        killed = int(counts["killed"])
        # FIX-MUTATION-INT-SCORE: floor, as an int. Floats are not canonicalisable.
        score = (killed * 100) // total if total else 0
        payload = {
            "scorePct": int(score),
            "killed": killed,
            "survived": int(counts.get("survived", 0)),
            "timeout": int(counts.get("timeout", 0)),
            "noCoverage": int(counts.get("noCoverage", 0)),
            "total": total,
            "scope": scope,
            "tool": tool,
            "toolVersion": self._version(ctx, root, tool),
            "mutatedFileCount": int(counts.get("files", 0)),
            "changedFiles": list(changed or []),
            "detail": detail,
        }
        try:
            workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "mutation.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass
        return self.collected(ctx, payload,
                              note=f"{tool}: {score}% ({killed}/{total} killed, "
                                   f"{payload['survived']} survived, {payload['noCoverage']} "
                                   f"without coverage), scope={scope}")

    # --- detection -------------------------------------------------------------------------
    def _detect(self, ctx, root):
        if (root / "node_modules" / ".bin" / "stryker").exists():
            return "stryker"
        has_dotnet = bool(next(root.rglob("*.csproj"), None) or next(root.glob("*.sln"), None))
        if has_dotnet and self._runs(ctx, root, ["dotnet", "--version"]):
            return "stryker-net"
        if (root / "cosmic-ray.toml").exists() or next(root.glob("*.cosmic-ray.toml"), None):
            if self._runs(ctx, root, ["cosmic-ray", "--version"]):
                return "cosmic-ray"
        if self._runs(ctx, root, ["mutmut", "--version"]):
            return "mutmut"
        if (root / "package.json").exists() and self._runs(ctx, root, ["stryker", "--version"]):
            return "stryker"
        return None

    def _runs(self, ctx, root, argv):
        """A `--version` probe. Success is rc==0 and nothing else.

        A missing binary does NOT reliably surface as rc 127: inside a bwrap boundary the
        wrapper reports `execvp <tool>: No such file or directory` with rc 1, so "the tool is
        absent" and "the tool ran and failed" are indistinguishable by sentinel alone. A tool
        that exists answers `--version` with 0; anything else is treated as absent, which fails
        closed (ERROR evidence) rather than driving a tool that is not there.
        """
        res = self._exec(ctx, root, argv, 90)
        return bool(res is not None and res.returncode == 0)

    def _version(self, ctx, root, tool):
        argv = {
            "stryker": [self._stryker_bin(root) or "stryker", "--version"],
            "stryker-net": ["dotnet", "stryker", "--version"],
            "mutmut": ["mutmut", "--version"],
            "cosmic-ray": ["cosmic-ray", "--version"],
        }[tool]
        res = self._exec(ctx, root, argv, 90)
        if res is None or res.returncode != 0:
            return "unknown"
        line = ((res.stdout or "") + (res.stderr or "")).strip().splitlines()
        return line[0][:80] if line else "unknown"

    def _stryker_bin(self, root):
        local = root / "node_modules" / ".bin" / "stryker"
        return "node_modules/.bin/stryker" if local.exists() else None

    def _exec(self, ctx, root, argv, timeout):
        try:
            return ctx.adapter.run_target(argv=argv, cwd=str(root), timeout=timeout)
        except Exception:  # noqa: BLE001 — refused/failed: no signal, never a score
            return None

    def _changed_files(self, ctx, root):
        ref = str(ctx.option("mutation_ref", "HEAD") or "HEAD")
        try:
            res = ctx.adapter.run_internal(["git", "diff", "--name-only", ref],
                                           cwd=str(root), timeout=120)
        except Exception:  # noqa: BLE001
            return None
        if res.returncode != 0:
            return None
        return [f.strip() for f in (res.stdout or "").splitlines()
                if f.strip() and Path(f.strip()).suffix.lower() in SRC_EXT]

    # --- runners ----------------------------------------------------------------------------
    def _stryker_like(self, ctx, root, argv, timeout, label):
        pre = _reports(root)
        res = self._exec(ctx, root, argv, timeout)
        if res is None:
            return None, "the execution adapter refused or failed to run the mutation tool"
        if res.returncode in ERROR_RCS:
            return None, (f"the run did not complete (rc={res.returncode}: timeout / output limit / "
                          f"spawn failure); refusing to score a run that did not finish")
        if res.returncode != 0:
            tail = ((res.stdout or "") + (res.stderr or ""))[-400:].strip()
            return None, (f"{label} exited non-zero ({res.returncode}) — the mutation run FAILED. "
                          f"Refusing to score from any pre-existing report (stale evidence). {tail}")
        post = _reports(root)
        fresh = [p for p, m in post.items() if p not in pre or m > pre.get(p, 0)]
        for p in sorted(fresh):
            counts = parse_stryker_report(p)
            if counts:
                return counts, f"parsed {p}"
        return None, ("the run succeeded but produced no fresh, parseable mutation-report.json "
                      "(check the tool's mutate globs and test-runner config)")

    def _run_stryker(self, ctx, root, timeout, changed):
        binexe = self._stryker_bin(root)
        if not binexe:
            # Never `npx --yes`: it fetches LATEST at call time, so the measurement is not
            # reproducible and the tool is not the pinned one bootstrap installed.
            binexe = "stryker"
        argv = [binexe, "run", "--reporters", "json,clear-text"]
        if changed:
            argv += ["--mutate", ",".join(changed)]
        return self._stryker_like(ctx, root, argv, timeout, "StrykerJS")

    def _run_stryker_net(self, ctx, root, timeout, changed):
        argv = ["dotnet", "stryker", "--reporter", "json", "--reporter", "progress"]
        if changed:
            argv += ["--mutate", ",".join(changed)]
        return self._stryker_like(ctx, root, argv, timeout, "Stryker.NET")

    def _run_mutmut(self, ctx, root, timeout, changed):
        argv = ["mutmut", "run", "--no-progress"]
        if changed:
            argv += ["--paths-to-mutate", ",".join(changed)]
        res = self._exec(ctx, root, argv, timeout)
        if res is None:
            return None, "the execution adapter refused or failed to run mutmut"
        if res.returncode in ERROR_RCS:
            return None, (f"mutmut did not complete (rc={res.returncode}: timeout / output limit / "
                          f"spawn failure); a run that did not finish has no score")
        results = self._exec(ctx, root, ["mutmut", "results"], 600)
        blob = (res.stdout or "") + (res.stderr or "")
        if results is not None:
            blob += (results.stdout or "") + (results.stderr or "")
        counts = parse_mutmut(blob)
        if counts is None:
            return None, "mutmut output could not be parsed into killed/survived counts"
        return counts, "parsed mutmut results"

    def _run_cosmic_ray(self, ctx, root, timeout, changed):
        cfg = "cosmic-ray.toml"
        if not (root / cfg).exists():
            found = next(root.glob("*.cosmic-ray.toml"), None)
            if found is None:
                return None, "no cosmic-ray.toml configuration in the run area"
            cfg = found.name
        # NOT under shipgate-workdir: the adapter RO-binds the gate's own state inside the
        # boundary, so a target-controlled tool cannot create its session there.
        session = ".shipgate-cosmic-ray.sqlite"
        for argv in (["cosmic-ray", "init", cfg, session],
                     ["cosmic-ray", "exec", cfg, session]):
            res = self._exec(ctx, root, argv, timeout)
            if res is None:
                return None, "the execution adapter refused or failed to run cosmic-ray"
            if res.returncode != 0:
                tail = ((res.stdout or "") + (res.stderr or ""))[-300:].strip()
                return None, f"`{' '.join(argv)}` failed (rc={res.returncode}): {tail}"
        res = self._exec(ctx, root, ["cr-report", session], 600)
        if res is None or res.returncode != 0:
            return None, "cr-report could not be run, so the session has no readable outcome"
        counts = parse_cosmic_ray((res.stdout or "") + (res.stderr or ""))
        if counts is None:
            return None, "cr-report output could not be parsed into killed/survived counts"
        return counts, "parsed cr-report"
