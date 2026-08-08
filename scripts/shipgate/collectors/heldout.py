"""HELDOUT collector — the compositional suite the Builder never saw, RUN AND READ.

Ported from v3.8 `vault.py` (stash/restore/clear + manifest integrity) and v3.8 `heldout.py`
(run binding + suite digests). What is preserved:

  * the vault-hidden assertion: a vault that resolves INSIDE the repo under test, under no
    ignored directory, means the held-out files were in the Builder's sight all along and get
    sealed as visible tests — the suite was never held out at all;
  * manifest integrity: a missing vault copy, a missing per-file checksum and a MODIFIED vault
    copy are three DIFFERENT failures with three different messages, and each refuses;
  * path containment: a manifest entry containing `..` or an absolute path would make restore
    a write-outside-the-repo primitive and clear a delete-outside-the-repo one;
  * the SUITE DIGEST, derived twice — once from the live vault bytes and once from the
    manifest's recorded checksums — so a swapped vault, a substituted manifest or a suite
    modified after execution all fail;
  * restore -> run -> clear, so the held-out files never linger in the tree.

STRIPPED, deliberately: v3.8's `heldout.py` also carried a whole trust-and-identity layer —
key material, producing-principal adjudication against an external trust policy, external
timestamps, nonces and release-manifest binding. None of that is Axis-B semantics; none of it
is imported, referenced or reimplemented here. What is kept is the part that answers "is this
result about THIS run and THIS suite": the suite digest and the runner digest.

FIX-HELDOUT-EVALUATED (the headline v3.8 defect): v3.8 BOUND the held-out result to the run
and never EVALUATED it — a held-out suite could fail and the gate still passed, because
nothing read the counts. This collector executes the suite and PARSES the runner's own
machine-readable output (pytest `--json-report`, then core `--junit-xml`, then the `-q`
summary; jest/vitest `--json`; `dotnet test --logger trx`) into total/passed/failed/errored.
`evaluated` is True ONLY when real counts were read out of real runner output. When the
output cannot be parsed,
`evaluated` is False and `detail` says why — it is never guessed, and
`heldout_evaluated` fails closed on it.
"""
import hashlib
import json
import re
import shutil
from pathlib import Path

from ..models.evidence import EvidenceKind
from ..util.hashing import sha256_file, sha256_text
from .base import Collector

RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127
ERROR_RCS = (RC_TIMEOUT, RC_OUTPUT_LIMIT, RC_SPAWN_FAILED)

#: Directories a vault may hide under while still being inside the repo path (v3.8 SKIP).
HIDDEN_PARENTS = {"node_modules", ".git", "shipgate-workdir", ".shipgate-vault", ".vault"}

#: Where a test runner may write its machine-readable report. NOT `shipgate-workdir`: the
#: adapter RO-binds the gate's own state inside the containment boundary, so target code cannot
#: write there. Created per run and removed again, so the run-area tree is left clean.
SCRATCH_DIR = ".shipgate-heldout"

_PYTEST_SUMMARY = re.compile(
    r"(?:(\d+)\s+passed)|(?:(\d+)\s+failed)|(?:(\d+)\s+errors?)|(?:(\d+)\s+skipped)", re.I)


def suite_map_digest(pairs):
    """v3.8 `_suite_map`: canonical sha256 over a {relpath: filehash} map.

    Two suites are the SAME iff every path AND every hash match, independent of disk order.
    """
    return hashlib.sha256(
        json.dumps(dict(pairs), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _load_manifest(vault):
    mp = Path(vault) / "heldout-manifest.json"
    if not mp.exists():
        return None, f"no held-out vault manifest at {mp}"
    try:
        man = json.loads(mp.read_text())
        if not isinstance(man, dict):
            raise ValueError("manifest is not a JSON object")
        files = man.get("heldout_files")
        if not isinstance(files, list) or any(not isinstance(m, str) for m in files):
            raise ValueError("heldout_files is not a list of strings")
    except Exception as exc:  # noqa: BLE001
        return None, (f"held-out vault manifest at {mp} cannot be parsed "
                      f"({type(exc).__name__}: {exc}); the suite cannot be accounted for")
    bad = [m for m in files if ".." in Path(m).parts or Path(m).is_absolute()]
    if bad:
        return None, (f"the manifest lists {len(bad)} entry/entries that leave the repo "
                      f"({bad[0]}); refusing to write or delete outside the repo under test")
    return man, "ok"


def vault_hidden(repo, vault):
    """v3.8 `assert_vault_hidden`, as an observation instead of a sys.exit."""
    try:
        rel = Path(vault).resolve().relative_to(Path(repo).resolve())
    except ValueError:
        return True, "vault is outside the repository under test"
    if set(rel.parts) & HIDDEN_PARENTS:
        return True, f"vault is inside the repo at {rel} but under an ignored directory"
    return False, (f"vault resolves INSIDE the repo under test at {rel}, under no ignored "
                   f"directory — held-out tests there stay in the Builder's sight")


def parse_pytest_json(path):
    try:
        doc = json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None
    summary = doc.get("summary") if isinstance(doc, dict) else None
    if not isinstance(summary, dict):
        return None
    passed = int(summary.get("passed", 0) or 0)
    failed = int(summary.get("failed", 0) or 0)
    errored = int(summary.get("error", 0) or 0) + int(summary.get("errors", 0) or 0)
    total = summary.get("total")
    total = int(total) if isinstance(total, int) else passed + failed + errored
    return {"total": total, "passed": passed, "failed": failed, "errored": errored}


def parse_junit_xml(path):
    """`--junit-xml` is CORE pytest (and understood by most JS/JVM runners too).

    It is preferred over the terminal summary because the summary line is suppressed entirely
    when the repo's own `addopts` already contains `-q` (`-q -q` = double quiet) — a real repo
    can silence the only thing a summary parser has to read.
    """
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return None
    m = re.search(r"<testsuite\b[^>]*>", text)
    if not m:
        return None
    attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(0)))
    if "tests" not in attrs:
        return None

    def _n(name):
        try:
            return int(attrs.get(name, 0) or 0)
        except ValueError:
            return 0

    total = _n("tests")
    failed = _n("failures")
    errored = _n("errors")
    skipped = _n("skipped")
    return {"total": total, "passed": max(0, total - failed - errored - skipped),
            "failed": failed, "errored": errored}


def parse_pytest_summary(text):
    """`5 passed, 1 failed, 2 errors in 0.12s`. None when no summary line is present."""
    tail = "\n".join((text or "").strip().splitlines()[-12:])
    passed = failed = errored = skipped = 0
    seen = False
    for m in _PYTEST_SUMMARY.finditer(tail):
        seen = True
        if m.group(1):
            passed += int(m.group(1))
        elif m.group(2):
            failed += int(m.group(2))
        elif m.group(3):
            errored += int(m.group(3))
        elif m.group(4):
            skipped += int(m.group(4))
    if not seen:
        return None
    return {"total": passed + failed + errored + skipped, "passed": passed,
            "failed": failed, "errored": errored}


def parse_jest_json(text_or_path):
    """jest `--json` and vitest `--reporter=json` share these fields."""
    doc = None
    p = Path(str(text_or_path))
    try:
        if p.is_file():
            doc = json.loads(p.read_text())
    except Exception:  # noqa: BLE001
        doc = None
    if doc is None:
        blob = str(text_or_path)
        start = blob.find("{")
        while start >= 0 and doc is None:
            try:
                doc = json.loads(blob[start:])
            except Exception:  # noqa: BLE001
                start = blob.find("{", start + 1)
    if not isinstance(doc, dict) or "numTotalTests" not in doc:
        return None
    total = int(doc.get("numTotalTests", 0) or 0)
    passed = int(doc.get("numPassedTests", 0) or 0)
    failed = int(doc.get("numFailedTests", 0) or 0)
    errored = int(doc.get("numRuntimeErrorTestSuites", 0) or 0)
    return {"total": total, "passed": passed, "failed": failed, "errored": errored}


def parse_trx(path):
    """`dotnet test --logger trx` writes <Counters total=".." passed=".." failed=".." .../>."""
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return None
    m = re.search(r"<Counters\b[^>]*>", text)
    if not m:
        return None
    attrs = dict(re.findall(r'(\w+)="(\d+)"', m.group(0)))
    if "total" not in attrs:
        return None
    total = int(attrs.get("total", 0))
    passed = int(attrs.get("passed", 0))
    failed = int(attrs.get("failed", 0))
    errored = int(attrs.get("error", 0)) + int(attrs.get("aborted", 0))
    return {"total": total, "passed": passed, "failed": failed, "errored": errored}


class HeldOutCollector(Collector):
    """Restore the held-out suite, run it, read its real counts, then remove it again.

    Options: `vault` (default `<workdir>/.vault`), `heldout_cmd` (an explicit runner command),
    `heldout_timeout` (default 1800).
    """

    kind = EvidenceKind.HELDOUT
    name = "heldout"
    version = "4.2.4"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        vault = Path(ctx.option("vault") or (workdir / ".vault"))
        timeout = int(ctx.option("heldout_timeout", 1800) or 1800)

        hidden, hidden_detail = vault_hidden(root, vault)
        man, reason = _load_manifest(vault)
        if man is None:
            return self.collected(ctx, {
                "suites": [], "vaultHidden": hidden, "runnerDigest": "",
                "detail": reason,
            }, note=reason, uncovered=["held-out suite: no usable vault manifest"])

        files = list(man.get("heldout_files") or [])
        shas = man.get("heldout_sha") if isinstance(man.get("heldout_sha"), dict) else {}
        groups = self._suites(man, files)
        if not groups:
            return self.collected(ctx, {
                "suites": [], "vaultHidden": hidden, "runnerDigest": "",
                "detail": "the vault manifest lists no held-out file",
            }, note="the vault manifest lists no held-out file",
               uncovered=["held-out suite: empty manifest"])

        suites, runner_digests = [], []
        for suite_id, members in groups:
            suite = self._one_suite(ctx, root, workdir, vault, suite_id, members, shas, timeout)
            runner_digests.append(suite.pop("_runnerDigest", ""))
            suites.append(suite)

        payload = {
            "suites": suites,
            "vaultHidden": bool(hidden),
            "runnerDigest": sha256_text("|".join(runner_digests)),
            "vaultDetail": hidden_detail,
            "manifestDigest": self._manifest_digest(vault),
        }
        evaluated = sum(1 for s in suites if s["evaluated"])
        note = (f"{len(suites)} held-out suite(s); {evaluated} evaluated; "
                f"{sum(s['failed'] + s['errored'] for s in suites)} failure(s)/error(s)")
        return self.collected(ctx, payload, note=note)

    # --- suites -------------------------------------------------------------------------
    def _suites(self, man, files):
        declared = man.get("suites")
        if isinstance(declared, list) and declared:
            out = []
            for s in declared:
                if not isinstance(s, dict):
                    continue
                members = [f for f in (s.get("files") or []) if isinstance(f, str) and f in files]
                if members:
                    out.append((str(s.get("suiteId") or s.get("id") or "heldout"), sorted(members)))
            if out:
                return out
        return [("heldout", sorted(files))] if files else []

    def _manifest_digest(self, vault):
        p = Path(vault) / "heldout-manifest.json"
        try:
            return sha256_file(p)
        except OSError:
            return ""

    def _one_suite(self, ctx, root, workdir, vault, suite_id, members, shas, timeout):
        vh = Path(vault) / "heldout"
        problems = []
        live_pairs, sealed_pairs = {}, {}
        for rel in members:
            src = vh / rel
            if not src.is_file():
                problems.append(f"the vault copy of {rel} is gone; the suite cannot be restored in full")
                continue
            recorded = shas.get(rel)
            if not isinstance(recorded, str):
                problems.append(f"{rel} is listed with no recorded checksum, so tampering with it "
                                f"cannot be detected")
                continue
            try:
                live = sha256_file(src)
            except OSError as exc:
                problems.append(f"{rel} is unreadable in the vault ({type(exc).__name__}: {exc})")
                continue
            if live != recorded:
                problems.append(f"TAMPER: the vault copy of {rel} was modified since it was stashed")
                continue
            live_pairs[rel] = live
            sealed_pairs[rel] = recorded

        live_digest = suite_map_digest(live_pairs) if live_pairs else ""
        sealed_digest = suite_map_digest(sealed_pairs) if sealed_pairs else ""
        bound = bool(live_pairs) and live_digest == sealed_digest and not problems

        # A held-out file already sitting in the repo was in the Builder's sight; whatever it
        # proves, it does not prove the compositional property this suite exists to prove.
        visible = [rel for rel in members if (root / rel).exists()]
        if visible:
            bound = False
            problems.append(f"{len(visible)} held-out file(s) were already present in the repo "
                            f"before restore ({visible[0]}), so the suite was not held out")

        result = {
            "suiteId": suite_id,
            "bound": bool(bound),
            "evaluated": False,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errored": 0,
            "bindingDigest": live_digest,
            "detail": "; ".join(problems) if problems else "",
            "_runnerDigest": "",
        }
        if not bound:
            result["detail"] = result["detail"] or "the suite is not bound to this run"
            return result

        restored = []
        try:
            for rel in members:
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((vh / rel).read_bytes())
                restored.append(dest)
            counts, detail, runner = self._run(ctx, root, workdir, members, timeout)
        except OSError as exc:
            counts, detail, runner = None, f"restore failed ({type(exc).__name__}: {exc})", ""
        finally:
            # `clear`: the held-out files never linger where the Builder can see them, and the
            # runner's scratch reports leave the run-area tree exactly as they found it.
            for p in restored:
                try:
                    p.unlink()
                except OSError:
                    pass
            shutil.rmtree(root / SCRATCH_DIR, ignore_errors=True)

        result["_runnerDigest"] = sha256_text(runner or "")
        if counts is None:
            # FIX-HELDOUT-EVALUATED: no counts means NOT evaluated. Never guessed.
            result["evaluated"] = False
            result["detail"] = detail
            return result
        result.update({
            "evaluated": True,
            "total": int(counts["total"]),
            "passed": int(counts["passed"]),
            "failed": int(counts["failed"]),
            "errored": int(counts["errored"]),
            "detail": detail,
            "runner": runner,
        })
        return result

    # --- execution ----------------------------------------------------------------------
    def _exec(self, ctx, root, argv=None, command=None, timeout=1800):
        try:
            return ctx.adapter.run_target(argv=argv, command=command, cwd=str(root),
                                          timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return exc

    def _run(self, ctx, root, workdir, members, timeout):
        """(counts|None, detail, runner-description). Machine-readable formats first."""
        explicit = (ctx.option("heldout_cmd") or "").strip()
        # SCRATCH, not the workdir: the adapter RO-BINDS `<run area>/shipgate-workdir` inside
        # the boundary, so the gate's own state cannot be rewritten by target code — which also
        # means a test runner cannot write its report there. The scratch directory lives at the
        # run-area root (writable), and `_one_suite` removes it again so the tree stays clean.
        scratch = SCRATCH_DIR
        try:
            (root / scratch).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        if explicit:
            res = self._exec(ctx, root, command=explicit, timeout=timeout)
            if not hasattr(res, "returncode"):
                return None, f"the runner could not be started ({res})", explicit
            counts = (parse_jest_json(res.stdout or "")
                      or parse_pytest_summary((res.stdout or "") + (res.stderr or "")))
            if counts is None:
                return None, ("the declared held-out runner produced no machine-readable outcome "
                              "(no pytest summary, no jest/vitest JSON); pass a runner that emits "
                              "one — a green exit code is not an evaluated suite"), explicit
            return counts, "parsed the declared runner's output", explicit

        py = [m for m in members if m.endswith(".py")]
        js = [m for m in members if Path(m).suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs")]
        cs = [m for m in members if m.endswith(".cs")]
        if py:
            return self._run_pytest(ctx, root, scratch, py, timeout)
        if js:
            return self._run_js(ctx, root, scratch, js, timeout)
        if cs:
            return self._run_dotnet(ctx, root, scratch, timeout)
        return None, (f"no runner is known for the held-out file types "
                      f"({', '.join(sorted({Path(m).suffix for m in members}))}); declare one with "
                      f"the `heldout_cmd` option"), ""

    def _run_pytest(self, ctx, root, scratch, members, timeout):
        report = f"{scratch}/heldout-pytest.json"
        abs_report = root / report
        try:
            if abs_report.exists():
                abs_report.unlink()
        except OSError:
            pass
        argv = ["python3", "-m", "pytest", "-q", "--json-report",
                f"--json-report-file={report}", *members]
        runner = " ".join(argv)
        res = self._exec(ctx, root, argv=argv, timeout=timeout)
        if hasattr(res, "returncode") and abs_report.exists():
            counts = parse_pytest_json(abs_report)
            if counts is not None:
                return counts, "parsed pytest --json-report", runner
        # The plugin is absent (pytest exits with a usage error and runs nothing). Fall back to
        # --junit-xml, which is core pytest and — unlike the terminal summary — cannot be
        # silenced by the repo's own `addopts = -q`.
        junit = f"{scratch}/heldout-junit.xml"
        abs_junit = root / junit
        try:
            if abs_junit.exists():
                abs_junit.unlink()
        except OSError:
            pass
        argv = ["python3", "-m", "pytest", "-q", f"--junit-xml={junit}", *members]
        runner = " ".join(argv)
        res = self._exec(ctx, root, argv=argv, timeout=timeout)
        if not hasattr(res, "returncode"):
            return None, f"pytest could not be started ({res})", runner
        if res.returncode in ERROR_RCS or res.timed_out:
            return None, (f"the held-out run did not complete (rc={res.returncode}, "
                          f"timedOut={res.timed_out}); its outcome is unknown"), runner
        if abs_junit.exists():
            counts = parse_junit_xml(abs_junit)
            if counts is not None:
                return counts, "parsed the pytest JUnit XML report", runner
        counts = parse_pytest_summary((res.stdout or "") + (res.stderr or ""))
        if counts is None:
            tail = ((res.stdout or "") + (res.stderr or ""))[-300:].strip()
            return None, (f"pytest produced neither a JUnit XML report nor a readable summary "
                          f"line, so pass/fail counts could not be read (rc={res.returncode}): "
                          f"{tail}"), runner
        return counts, "parsed the pytest -q summary line", runner

    def _run_js(self, ctx, root, scratch, members, timeout):
        out = f"{scratch}/heldout-js.json"
        abs_out = root / out
        try:
            if abs_out.exists():
                abs_out.unlink()
        except OSError:
            pass
        candidates = []
        if (root / "node_modules" / ".bin" / "vitest").exists():
            candidates.append((["node_modules/.bin/vitest", "run", "--reporter=json",
                                f"--outputFile={out}", *members], "vitest"))
        if (root / "node_modules" / ".bin" / "jest").exists():
            candidates.append((["node_modules/.bin/jest", "--json", f"--outputFile={out}",
                                "--runTestsByPath", *members], "jest"))
        if not candidates:
            return None, ("neither vitest nor jest is installed in the run area's node_modules, so "
                          "the held-out suite has no machine-readable runner; declare one with the "
                          "`heldout_cmd` option"), ""
        last = ""
        for argv, tool in candidates:
            runner = " ".join(argv)
            res = self._exec(ctx, root, argv=argv, timeout=timeout)
            if not hasattr(res, "returncode"):
                last = f"{tool} could not be started ({res})"
                continue
            counts = None
            if abs_out.exists():
                counts = parse_jest_json(abs_out)
            if counts is None:
                counts = parse_jest_json(res.stdout or "")
            if counts is not None:
                return counts, f"parsed {tool} JSON output", runner
            last = (f"{tool} exited rc={res.returncode} but produced no parseable JSON report, so "
                    f"pass/fail counts could not be read")
        return None, last, ""

    def _run_dotnet(self, ctx, root, scratch, timeout):
        argv = ["dotnet", "test", "--logger", "trx;LogFileName=heldout.trx", "--results-directory",
                scratch]
        runner = " ".join(argv)
        res = self._exec(ctx, root, argv=argv, timeout=timeout)
        if not hasattr(res, "returncode"):
            return None, f"dotnet test could not be started ({res})", runner
        trx = root / scratch / "heldout.trx"
        counts = parse_trx(trx) if trx.exists() else None
        if counts is None:
            return None, (f"dotnet test produced no readable TRX counters (rc={res.returncode}), so "
                          f"pass/fail counts could not be read"), runner
        return counts, "parsed the dotnet test TRX counters", runner
