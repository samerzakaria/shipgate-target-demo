"""SECURITY collector — dependency advisories and committed secrets.

Ported from v3.8 `security.py`. SCOPE, unchanged, so the number is not over-read: this
collector covers exactly two things.

  1. DEPENDENCY audit — `npm audit --omit=dev --json` per JS package that has a lockfile
     (dev-only advisories excluded, matching the stated policy) and `pip-audit -f json`
     against the PROJECT's declared requirements rather than the ambient interpreter.
     Monorepos are walked: every nested package and every Python manifest, not just root.
  2. Committed-SECRET grep — a small set of HIGH-CONFIDENCE patterns (private-key blocks,
     cloud access keys, provider tokens). A smoke test, not a SAST engine.

It does NOT do SAST/taint analysis, container or IaC scanning, licence governance, an
authn/authz matrix, CORS/SSRF/upload/injection probing, header analysis, crypto review or
tenant-isolation checks. A favourable result here is not evidence about any of those.

Machine-readable tool output ONLY — never the human CLI text, which changes between minor
versions and cannot be parsed safely.

Every subprocess goes through `ctx.adapter.run_target`; nothing here imports `subprocess`
and nothing probes the PATH directly. A tool that will not start is recorded as MISSING,
which is not the same as, and never reads as, zero findings.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__",
             "coverage", "shipgate-workdir", ".vault", ".vite", "playwright-report",
             "test-results", "shipgate-ui-evidence"}
SEVERITIES = ("critical", "high", "moderate", "low")

# High-confidence committed-secret shapes only (a live private key or provider token).
# Deliberately NOT matching `password=` / `api_key=` generically — that is a false-positive
# geyser, not a signal.
SECRET_PATTERNS = [
    ("private-key-block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe-secret-key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
]
SCAN_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".py", ".cs", ".java", ".rb", ".go", ".php",
            ".env", ".yml", ".yaml", ".json", ".txt", ".config", ".xml", ".sh", ".ini",
            ".properties"}
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


#: The adapter's own sentinel for "the binary is not on PATH inside the boundary"
#: (execadapter.adapter.RC_SPAWN_FAILED). Duplicated as a literal rather than imported so
#: this module's import graph stays free of the execution machinery.
RC_SPAWN_FAILED = 127


def _spawn_failed(res):
    return res.returncode == RC_SPAWN_FAILED and "failed to spawn" in (res.stderr or "")


def parse_npm(text):
    """Findings from `npm audit --json`, across every format npm has shipped.

    A FAILED audit (`{"error":{"code":"ENOAUDIT"}}`, a lockfile npm cannot read, no network)
    is a JSON object with NO vulnerability collection — parsing it returned 0 and a failed
    scan read as clean. An error shape RAISES so the caller records the tool as unavailable.
    """
    d = json.loads(text)
    if not isinstance(d, dict):
        raise ValueError("npm audit json is not an object")
    if "error" in d and not any(k in d for k in ("metadata", "vulnerabilities", "advisories")):
        raise ValueError(f"npm audit reported an error, not results: {str(d.get('error'))[:200]}")

    findings = []
    vulns = d.get("vulnerabilities")
    if isinstance(vulns, dict):
        for name, v in sorted(vulns.items()):
            if not isinstance(v, dict):
                continue
            sev = str(v.get("severity", "")).lower()
            if sev not in SEVERITIES:
                continue
            titles = []
            for via in (v.get("via") or []):
                if isinstance(via, dict) and via.get("title"):
                    titles.append(str(via["title"]))
                elif isinstance(via, str):
                    titles.append(via)
            findings.append({
                "id": f"npm:{name}",
                "severity": sev,
                "package": str(v.get("name") or name),
                "detail": (f"range {v.get('range', '?')}: " + "; ".join(titles[:3]))[:400],
            })
    adv = d.get("advisories")
    if isinstance(adv, dict):
        for key, a in sorted(adv.items(), key=lambda kv: str(kv[0])):
            if not isinstance(a, dict):
                continue
            sev = str(a.get("severity", "")).lower()
            if sev not in SEVERITIES:
                continue
            findings.append({
                "id": f"npm-advisory:{key}",
                "severity": sev,
                "package": str(a.get("module_name") or "?"),
                "detail": str(a.get("title") or "")[:400],
            })

    # FIX-SECURITY-NEVER-UNDER-REPORT: npm's own `metadata.vulnerabilities` summary is
    # authoritative about HOW MANY advisories exist even when the detail collection is
    # abbreviated. Enumerated findings and the summary are reconciled by taking the LARGER
    # per severity, so an abbreviated detail list can never shrink the blocking count.
    summary = {}
    meta = (d.get("metadata") or {}).get("vulnerabilities")
    if isinstance(meta, dict):
        for k in SEVERITIES:
            try:
                summary[k] = int(meta.get(k, 0) or 0)
            except (TypeError, ValueError):
                summary[k] = 0
    return findings, summary


def parse_pip(text):
    """Findings from `pip-audit -f json`.

    FIX-PIPAUDIT-SEVERITY: pip-audit does not always carry a normalised severity. v3.8
    counted every recorded vulnerability as serious; the same conservatism is kept here by
    mapping an unlabelled advisory to `high`, and the detail says so, so the number is never
    read as a graded assessment.
    """
    d = json.loads(text)
    deps = d.get("dependencies") if isinstance(d, dict) else d
    findings = []
    if not isinstance(deps, list):
        raise ValueError("pip-audit json has no dependency list")
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or "?")
        for v in (dep.get("vulns") or []):
            if not isinstance(v, dict):
                continue
            sev = str(v.get("severity") or "").lower()
            if sev not in SEVERITIES:
                sev = "high"
                suffix = " (pip-audit reported no normalised severity; counted as high)"
            else:
                suffix = ""
            findings.append({
                "id": f"pip:{v.get('id', '?')}",
                "severity": sev,
                "package": f"{name}=={dep.get('version', '?')}",
                "detail": (str(v.get("description") or v.get("id") or "")[:300] + suffix),
            })
    return findings


def _manifests(root):
    """Every JS package with a lockfile and every Python manifest — monorepo aware."""
    js, py = [], []
    for f in sorted(root.rglob("*")):
        try:
            rel = f.relative_to(root)
        except ValueError:
            continue
        if not f.is_file() or set(rel.parts) & SKIP_DIRS:
            continue
        if f.name == "package.json":
            if any((f.parent / lk).exists() for lk in LOCKFILES):
                js.append(f.parent)
        elif f.name in ("requirements.txt", "pyproject.toml", "Pipfile"):
            py.append(f)
    return js, py


def scan_secrets(root):
    """High-confidence committed-secret grep. Returns [{file, line, rule}]."""
    hits, seen = [], set()
    for f in sorted(root.rglob("*")):
        try:
            rel = f.relative_to(root)
        except ValueError:
            continue
        if not f.is_file() or set(rel.parts) & SKIP_DIRS:
            continue
        if f.suffix.lower() not in SCAN_EXT and f.name != ".env":
            continue
        try:
            if f.stat().st_size > 2_000_000:
                continue
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for rule, pat in SECRET_PATTERNS:
            m = pat.search(text)
            if not m:
                continue
            key = (rel.as_posix(), rule)
            if key in seen:
                continue
            seen.add(key)
            # FIX-SECRETS-LINE: v3.8 recorded only the file. The typed contract carries a
            # line, and a reviewer needs it to confirm or rotate the credential.
            hits.append({"file": rel.as_posix(), "line": text.count("\n", 0, m.start()) + 1,
                         "rule": rule})
    return hits


class SecurityCollector(Collector):
    """Dependency advisories (machine-readable) plus a committed-secret grep."""

    kind = EvidenceKind.SECURITY
    name = "security"
    version = "4.2.4"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")

        js_pkgs, py_manifests = _manifests(root)
        findings, tools_run, tools_missing, unaudited = [], [], [], []
        summary_total = {k: 0 for k in SEVERITIES}
        timeout = int(ctx.option("audit_timeout", 300) or 300)

        for pkgdir in js_pkgs:
            rel = pkgdir.relative_to(root).as_posix() or "."
            # Use the auditor that matches the lockfile: running `npm audit` against a
            # yarn/pnpm project fails, and that failure must read as unaudited, not clean.
            if (pkgdir / "pnpm-lock.yaml").exists():
                argv, tool = ["pnpm", "audit", "--json"], "pnpm audit"
            elif (pkgdir / "yarn.lock").exists():
                # yarn v1 emits NDJSON and yarn v2+ moved the command; neither is a stable
                # machine-readable contract, so the package is recorded as UNAUDITED rather
                # than parsed by guesswork.
                unaudited.append(f"{rel}: yarn lockfile — no stable JSON audit; recorded as "
                                 f"unaudited, NOT clean")
                tools_missing.append(f"yarn audit ({rel})")
                continue
            else:
                argv, tool = ["npm", "audit", "--omit=dev", "--json"], "npm audit"
            try:
                res = ctx.adapter.run_target(argv=argv, cwd=pkgdir, timeout=timeout,
                                             network=True, label=f"{tool} ({rel})")
            except Exception as exc:  # noqa: BLE001 — a refused execution is evidence
                unaudited.append(f"{rel}: {tool} could not be executed ({type(exc).__name__})")
                tools_missing.append(f"{tool} ({rel})")
                continue
            if _spawn_failed(res) or res.timed_out or res.output_truncated:
                why = ("not found inside the boundary" if _spawn_failed(res)
                       else "timed out" if res.timed_out else "output limit exceeded")
                unaudited.append(f"{rel}: {tool} {why} — recorded as unaudited, NOT zero findings")
                tools_missing.append(f"{tool} ({rel})")
                continue
            try:
                got, summary = parse_npm(res.stdout)
            except Exception as exc:  # noqa: BLE001
                unaudited.append(f"{rel}: {tool} output unparseable ({type(exc).__name__}: "
                                 f"{str(exc)[:120]}) — recorded as unaudited, NOT zero findings")
                tools_missing.append(f"{tool} ({rel})")
                continue
            findings += [{**g, "id": f"{g['id']}@{rel}"} for g in got]
            for k in SEVERITIES:
                summary_total[k] += summary.get(k, 0)
            if tool not in tools_run:
                tools_run.append(tool)

        for man in py_manifests:
            rel = man.relative_to(root).as_posix()
            # Target the PROJECT's declared deps, not the ambient interpreter environment.
            if man.name == "requirements.txt":
                argv = ["pip-audit", "-r", man.name, "-f", "json"]
                scope = "requirements"
            else:
                argv = ["pip-audit", "-f", "json"]
                scope = "ambient environment (pyproject/Pipfile deps are not resolved to a lockfile)"
            try:
                res = ctx.adapter.run_target(argv=argv, cwd=man.parent, timeout=timeout,
                                             network=True, label=f"pip-audit ({rel})")
            except Exception as exc:  # noqa: BLE001
                unaudited.append(f"{rel}: pip-audit could not be executed ({type(exc).__name__})")
                tools_missing.append(f"pip-audit ({rel})")
                continue
            if _spawn_failed(res) or res.timed_out or res.output_truncated:
                why = ("not found inside the boundary" if _spawn_failed(res)
                       else "timed out" if res.timed_out else "output limit exceeded")
                unaudited.append(f"{rel}: pip-audit {why} — recorded as unaudited, NOT zero findings")
                tools_missing.append(f"pip-audit ({rel})")
                continue
            try:
                got = parse_pip(res.stdout)
            except Exception as exc:  # noqa: BLE001
                unaudited.append(f"{rel}: pip-audit output unparseable ({type(exc).__name__}) — "
                                 f"recorded as unaudited, NOT zero findings")
                tools_missing.append(f"pip-audit ({rel})")
                continue
            findings += [{**g, "id": f"{g['id']}@{rel}",
                          "detail": f"[{scope}] {g['detail']}"} for g in got]
            if "pip-audit" not in tools_run:
                tools_run.append("pip-audit")

        secrets = scan_secrets(root)
        tools_run.append("secret-scan")

        counts = {k: 0 for k in SEVERITIES}
        for g in findings:
            counts[g["severity"]] = counts.get(g["severity"], 0) + 1
        for k in SEVERITIES:
            counts[k] = max(counts[k], summary_total.get(k, 0))

        # FIX-SECURITY-SECRET-IS-A-FINDING: v3.8 added committed secrets to its blocking
        # `serious` number. In the typed payload the evaluator only reads `counts`, so a
        # secret recorded solely in `secrets` would leave counts at zero and the check would
        # PASS with a live key in the tree. Each secret is therefore also a critical finding.
        for s in secrets:
            findings.append({
                "id": f"secret:{s['rule']}:{s['file']}:{s['line']}",
                "severity": "critical",
                "package": "(committed secret)",
                "detail": f"{s['rule']} at {s['file']}:{s['line']} — rotate the credential and "
                          f"purge it from history",
            })
            counts["critical"] += 1

        payload = {
            "findings": findings,
            "counts": counts,
            "secrets": secrets,
            "toolsRun": sorted(set(tools_run)),
            "toolsMissing": sorted(set(tools_missing)),
            "unaudited": unaudited,
            "packagesFound": {"javascript": len(js_pkgs), "python": len(py_manifests)},
            "coverage": ("dependency audit + committed-secret grep ONLY; SAST, IaC, authz, "
                         "CORS, SSRF, headers, crypto and tenant isolation are NOT covered "
                         "and must be recorded as their own layers"),
        }

        if unaudited and not ctx.option("security_allow_partial"):
            # A tool that could not run is not evidence of zero. PARTIAL evidence would still
            # satisfy `security_clean`, so an unauditable manifest fails closed as ERROR.
            return self.error(
                ctx,
                f"{len(unaudited)} dependency manifest(s) could not be audited, so this scan "
                f"is not evidence of a clean dependency tree: " + "; ".join(unaudited[:3]),
                payload)

        uncovered = [f"unaudited: {u}" for u in unaudited]
        note = (f"{len(findings)} finding(s) "
                f"(critical={counts['critical']}, high={counts['high']}), "
                f"{len(secrets)} committed secret(s); tools: {', '.join(sorted(set(tools_run)))}")
        if not js_pkgs and not py_manifests:
            note += " | no JS or Python dependency manifest was found to audit"
            langs = [l for l in (ctx.stack or {}).get("languages", []) if isinstance(l, str)]
            unsupported = [l for l in langs
                           if l not in ("javascript/typescript", "python")]
            if unsupported:
                # A .NET / Go / Java tree has dependencies this collector cannot audit at all.
                # Saying nothing would present "0 findings" as coverage of a language nothing
                # here looked at.
                uncovered.append("dependency-audit: no auditor for " + ", ".join(unsupported))
        return self.collected(ctx, payload, note=note, uncovered=uncovered)
