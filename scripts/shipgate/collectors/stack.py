"""STACK collector — what this repository actually is.

Ported from v3.8 `detect_stack.py` (`detect` + `detect_monorepo`), keeping its heuristics
intact and re-shaping the result into the typed STACK payload the semantic layer reads.

AUTHORITY RULE (v4.0): manifests, lockfiles, build/deployment config and source are the
ONLY authoritative inputs. A requirements document (BRD / HLD / design-system note /
wireframe pack) may *select* a technology only when it EXPLICITLY mandates one, and even
then it can never contradict a lockfile — a lockfile is what the machine will actually
install. Every document-sourced selection is recorded in `sources`.

Filesystem reads only; no process is spawned, so nothing here touches the adapter.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__",
             "coverage", "shipgate-workdir", ".vault", ".vite", "playwright-report",
             "test-results", "target", "bin", "obj"}

#: (dependency name, contributes a user interface)
JS_FRAMEWORKS = (
    ("next", True), ("react", True), ("vue", True), ("svelte", True), ("@angular/core", True),
    ("express", False), ("fastify", False), ("@nestjs/core", False), ("koa", False),
    ("hono", False), ("vite", True),
)
PY_FRAMEWORKS = (
    ("fastapi", False), ("flask", False), ("django", False), ("streamlit", True),
    ("gradio", True),
)
DOTNET_MARKERS = (
    ("microsoft.aspnetcore", "aspnet-core"), ("volo.abp", "abp"),
    ("microsoft.entityframeworkcore", "ef-core"), ("hangfire", "hangfire"),
    ("masstransit", "masstransit"), ("fluentvalidation", "fluentvalidation"),
)
UI_DIR_MARKERS = ("public", "static", "templates", "index.html", "src/index.html")

#: Documents that may *mandate* a technology. Never authoritative on their own.
REQ_DOC_RE = re.compile(
    r"(brd|hld|prd|requirements?|spec|design[-_ ]?system|wireframes?|architecture|adr)",
    re.I)
REQ_DOC_EXT = {".md", ".txt", ".rst", ".adoc"}
#: An EXPLICIT mandate: a normative verb followed, within one clause, by a known technology.
MANDATE_RE = re.compile(
    r"\b(?:must|shall|is\s+required\s+to|are\s+required\s+to|will\s+be)\s+"
    r"(?:be\s+)?(?:built|implemented|developed|written|deployed|use|used|using|run)\b"
    r"[^.\n]{0,100}", re.I)
#: Vocabulary a mandate may select from. Anything outside this list is ignored rather than
#: guessed — a prose noun is not a stack.
MANDATE_VOCAB = {
    "react": "react", "next.js": "next", "nextjs": "next", "vue": "vue", "svelte": "svelte",
    "angular": "@angular/core", "express": "express", "fastify": "fastify",
    "nestjs": "@nestjs/core", "nest.js": "@nestjs/core", "django": "django",
    "flask": "flask", "fastapi": "fastapi", "streamlit": "streamlit",
    "asp.net": "aspnet-core", "aspnet": "aspnet-core",
}
MANDATE_LANGS = {
    "typescript": "javascript/typescript", "javascript": "javascript/typescript",
    "python": "python", "c#": "csharp/.net", "csharp": "csharp/.net",
}


def _read(p):
    try:
        return Path(p).read_text(errors="ignore")
    except Exception:
        return ""


def _rel(root, p):
    try:
        return Path(p).relative_to(root).as_posix()
    except Exception:
        return str(p)


def _detect_one(root, base):
    """v3.8 `detect()`, per-package. Returns the raw dict the v3.8 code produced."""
    base = Path(base)
    out = {"languages": [], "frameworks": [], "ui": False, "package_managers": [],
           "start": [], "test": [], "build": [], "entry": [], "sources": [],
           "notes": [], "manifest": False, "lockfile": False}

    pkg_path = base / "package.json"
    if pkg_path.exists():
        out["manifest"] = True
        out["sources"].append(_rel(root, pkg_path))
        out["languages"].append("javascript/typescript")
        for lock, pm in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"),
                         ("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm")):
            if (base / lock).exists():
                out["package_managers"].append(pm)
                out["lockfile"] = True
                out["sources"].append(_rel(root, base / lock))
                break
        else:
            out["package_managers"].append("npm")
        try:
            pkg = json.loads(_read(pkg_path))
            deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
            for fw, is_ui in JS_FRAMEWORKS:
                if fw in deps:
                    out["frameworks"].append(fw)
                    out["ui"] = out["ui"] or is_ui
            scripts = pkg.get("scripts") or {}
            for k in ("dev", "start", "serve", "preview"):
                if k in scripts:
                    out["start"].append(f"npm run {k}")
            for k in ("test", "test:unit", "test:e2e"):
                if k in scripts:
                    out["test"].append(f"npm run {k}")
            # v3.8 POINT 5: record the production build so the gate can exercise the BUILT
            # artifact (build -> start) rather than the dev server.
            for k in ("build", "build:prod", "compile"):
                if k in scripts:
                    out["build"].append(f"npm run {k}")
            if pkg.get("main"):
                out["entry"].append(str(pkg["main"]))
        except Exception as exc:
            out["notes"].append(f"package.json parse failed: {type(exc).__name__}")

    py_markers = [p for p in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
                  if (base / p).exists()]
    if py_markers or list(base.glob("*.py")):
        out["languages"].append("python")
        if py_markers:
            out["manifest"] = True
            out["sources"].extend(_rel(root, base / p) for p in py_markers)
        if (base / "uv.lock").exists():
            out["package_managers"].append("uv")
            out["lockfile"] = True
            out["sources"].append(_rel(root, base / "uv.lock"))
        elif (base / "poetry.lock").exists():
            out["package_managers"].append("poetry")
            out["lockfile"] = True
            out["sources"].append(_rel(root, base / "poetry.lock"))
        else:
            out["package_managers"].append("pip")
        body = _read(base / "pyproject.toml") + _read(base / "requirements.txt")
        for fw, is_ui in PY_FRAMEWORKS:
            if re.search(rf"\b{re.escape(fw)}\b", body, re.I):
                out["frameworks"].append(fw)
                out["ui"] = out["ui"] or is_ui
        for cand in ("main.py", "app.py", "manage.py", "src/main.py", "server.py"):
            if (base / cand).exists():
                out["entry"].append(cand)
        if "fastapi" in out["frameworks"]:
            out["start"].append("uvicorn main:app --port 8000")
        if "flask" in out["frameworks"]:
            out["start"].append("flask run")
        if "django" in out["frameworks"]:
            out["start"].append("python manage.py runserver")
        if (base / "pytest.ini").exists() or "pytest" in body:
            out["test"].append("pytest -x -q")

    # .NET / ASP.NET Core — a Tier-2 stack. v3.8 note preserved: a .NET backend must not go
    # DARK (it once reported "no markers" and zero routes).
    csproj = next(base.rglob("*.csproj"), None)
    if csproj is not None or next(base.glob("*.sln"), None) or next(base.rglob("*.cs"), None):
        out["languages"].append("csharp/.net")
        out["package_managers"].append("nuget")
        if csproj is not None:
            out["manifest"] = True
            out["sources"].append(_rel(root, csproj))
        blob = "".join(_read(p) for p in list(base.rglob("*.csproj"))[:20]).lower()
        for marker, note in DOTNET_MARKERS:
            if marker in blob:
                out["frameworks"].append(note)
        if next(base.rglob("Program.cs"), None) or next(base.rglob("Startup.cs"), None):
            out["entry"].append("Program.cs")
        out["start"].append("dotnet run")
        out["test"].append("dotnet test")
        out["build"].append("dotnet publish -c Release")
        out["notes"].append(
            ".NET/ASP.NET Core is Tier-2: route extraction is HEURISTIC (attribute routing + "
            "minimal APIs); conventional controllers and remote-service proxies are NOT "
            "enumerated. Reconcile against the running app's OpenAPI document by hand.")

    for p, note in (("docker-compose.yml", "docker compose up"), ("compose.yaml", "docker compose up"),
                    ("Dockerfile", "Dockerfile present"), ("Makefile", "Makefile targets present")):
        if (base / p).exists():
            out["notes"].append(note)
            out["sources"].append(_rel(root, base / p))

    if any((base / d).exists() for d in UI_DIR_MARKERS):
        out["ui"] = True
    return out


def _mandates(root):
    """EXPLICIT technology mandates found in requirements documents.

    Returns (frameworks, languages, sources). A mandate is only recorded when a normative
    verb (must / shall / is required to) is followed within the same clause by a known
    technology name. Prose that merely mentions a technology selects nothing.
    """
    fws, langs, sources = {}, {}, []
    root = Path(root)
    seen = 0
    for f in sorted(root.rglob("*")):
        if seen > 400:
            break
        try:
            parts = set(f.relative_to(root).parts)
        except ValueError:
            continue
        if parts & SKIP_DIRS or not f.is_file():
            continue
        if f.suffix.lower() not in REQ_DOC_EXT:
            continue
        rel = f.relative_to(root).as_posix()
        if not REQ_DOC_RE.search(rel):
            continue
        seen += 1
        try:
            if f.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        text = _read(f)
        for m in MANDATE_RE.finditer(text):
            clause = m.group(0).lower()
            for token, canonical in MANDATE_VOCAB.items():
                if token in clause:
                    fws.setdefault(canonical, rel)
            for token, canonical in MANDATE_LANGS.items():
                if token in clause:
                    langs.setdefault(canonical, rel)
    for canonical, rel in sorted(fws.items()):
        sources.append(f"requirements-doc:{rel}#explicit-mandate:{canonical}")
    for canonical, rel in sorted(langs.items()):
        sources.append(f"requirements-doc:{rel}#explicit-mandate-language:{canonical}")
    return fws, langs, sources


class StackCollector(Collector):
    """Detect languages, frameworks, package managers, commands and entry points."""

    kind = EvidenceKind.STACK
    name = "stack"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            # v3.8 refused a nonexistent path rather than reporting "a real repo with no
            # markers", which downstream read as "no UI, no tests". Same refusal here.
            return self.error(ctx, f"run area is not a directory: {root}")

        root_det = _detect_one(root, root)
        packages, monorepo_dirs = [], []
        for pkg in sorted(root.glob("*/package.json")) + sorted(root.glob("*/*/package.json")):
            if set(pkg.relative_to(root).parts) & SKIP_DIRS:
                continue
            rel = pkg.parent.relative_to(root).as_posix()
            sub = _detect_one(root, pkg.parent)
            # v3.8 SA-09: sub-package commands must be runnable from the repo root.
            sub["start"] = [c.replace("npm run ", f"npm --prefix {rel} run ", 1)
                            for c in sub["start"] if c.startswith("npm run ")]
            sub["test"] = [c.replace("npm run ", f"npm --prefix {rel} run ", 1)
                           for c in sub["test"] if c.startswith("npm run ")]
            sub["build"] = [c.replace("npm run ", f"npm --prefix {rel} run ", 1)
                            for c in sub["build"] if c.startswith("npm run ")]
            sub["entry"] = [f"{rel}/{e}" for e in sub["entry"]]
            packages.append(sub)
            monorepo_dirs.append(rel)

        languages, frameworks, pms = list(root_det["languages"]), list(root_det["frameworks"]), \
            list(root_det["package_managers"])
        entry, start, test, build = (list(root_det["entry"]), list(root_det["start"]),
                                     list(root_det["test"]), list(root_det["build"]))
        sources, notes = list(root_det["sources"]), list(root_det["notes"])
        ui = bool(root_det["ui"])
        has_manifest = bool(root_det["manifest"])
        has_lockfile = bool(root_det["lockfile"])
        for sub in packages:
            languages += sub["languages"]
            frameworks += sub["frameworks"]
            pms += sub["package_managers"]
            entry += sub["entry"]
            start += sub["start"]
            test += sub["test"]
            build += sub["build"]
            sources += sub["sources"]
            notes += sub["notes"]
            ui = ui or bool(sub["ui"])
            has_manifest = has_manifest or sub["manifest"]
            has_lockfile = has_lockfile or sub["lockfile"]

        monorepo = bool(packages)
        if monorepo:
            try:
                root_scripts = json.loads(_read(root / "package.json") or "{}").get("scripts")
            except Exception as exc:
                root_scripts = None  # a malformed ROOT manifest must not crash the walk
                notes.append(f"root package.json parse failed: {type(exc).__name__}")
            if not root_scripts:
                notes.append("monorepo: root has no scripts; commands come from sub-packages")

        # --- requirements documents: selection only, never override -----------------------
        mandated_fw, mandated_lang, doc_sources = _mandates(root)
        for canonical, rel in sorted(mandated_fw.items()):
            if canonical in frameworks:
                continue
            if has_lockfile or has_manifest:
                # A prose document cannot introduce a framework the manifests do not carry.
                # Record the divergence; never let it decide the stack.
                notes.append(
                    f"requirements doc {rel} mandates {canonical!r} but no manifest/lockfile "
                    f"declares it — manifests are authoritative; NOT added to the stack")
            else:
                frameworks.append(canonical)
                notes.append(f"{canonical!r} selected from an explicit mandate in {rel} "
                             f"(no manifest present to be authoritative)")
        for canonical, rel in sorted(mandated_lang.items()):
            if canonical not in languages and not has_manifest:
                languages.append(canonical)
        sources += doc_sources

        def uniq(seq):
            return list(dict.fromkeys(x for x in seq if x))

        languages, frameworks = uniq(languages), uniq(frameworks)
        pms, entry = uniq(pms), uniq(entry)
        start, test, build, sources = uniq(start), uniq(test), uniq(build), uniq(sources)

        # --- ui: a REAL bool, or omitted ---------------------------------------------------
        # FIX-STACK-UI-FAIL-CLOSED: v3.8 initialised ui=False and shipped that default even
        # when it had recognised nothing at all, which told the caller to skip the UI /
        # accessibility layers on an app it never understood. Here a negative is only
        # asserted when there was something to be negative about; otherwise the key is
        # OMITTED, which the applicability resolver treats as "applicable" (fail closed).
        payload = {
            "languages": languages,
            "frameworks": frameworks,
            "packageManagers": pms,
            "commands": {
                "test": test[0] if test else None,
                "build": build[0] if build else None,
                "start": start[0] if start else None,
            },
            "entryPoints": entry,
            "monorepo": monorepo,
            "sources": sources,
        }
        if ui:
            payload["ui"] = True
        elif languages and (frameworks or entry):
            payload["ui"] = False
        else:
            notes.append("ui could not be determined; the key is omitted so UI-conditional "
                         "checks stay applicable")

        # --- confidence ---------------------------------------------------------------------
        if has_lockfile and frameworks:
            confidence = "high"
        elif has_manifest:
            confidence = "medium"
        else:
            confidence = "low"
        payload["confidence"] = confidence

        # Extra, non-contract fields the operator needs; the evaluator ignores them.
        payload["alternateCommands"] = {"test": test, "build": build, "start": start}
        payload["monorepoPackages"] = monorepo_dirs
        payload["notes"] = notes

        uncovered = []
        if not languages:
            # v3.8 printed "No JS/Python/.NET markers found". Silence here would let a Go /
            # Rust / Java repo look like a repo with nothing in it.
            uncovered.append("language-detection: no JS/TS, Python or .NET markers found")
        return self.collected(ctx, payload,
                              note=f"{len(languages)} language(s), {len(frameworks)} framework(s), "
                                   f"confidence={confidence}",
                              uncovered=uncovered)
