"""LEDGER collector — the capability ledger.

Ported from v3.8 `ledger.py` (`extract` + `merge` + `detect_mocks`). Everything that made
the v3.8 extractor trustworthy is preserved verbatim in behaviour:

  * minified / bundled / generated files are skipped (SA-02);
  * comments are blanked in place so a commented-out route is not a route and line numbers
    stay accurate (SA-17);
  * `app.use('<prefix>', router)` mount resolution, including the same-file
    `const router = express.Router()` case, keyed by (file, receiver) so a prefix belongs
    to that router only (SA-03/11);
  * router-vs-client receiver classification, so `http.post(...)` / `axios.get(...)` is a
    CALL, not a route definition;
  * balanced-brace `fetch` options parsing (a regex silently falls through to GET);
  * env-with-fallback base resolution (`API_URL` -> `/api`) (SA-14);
  * Python (Flask / FastAPI / Django), NestJS, .NET attribute + minimal-API extraction, the
    ABP / Angular HttpClient call-site recovery, and the .NET async / Angular flow
    inventories (Step 10b);
  * the mock policy: a test that mocks X yields NO evidence about X.

The collector does not spawn processes; it reads the run area and merges the RUNTIME_PROBE
and UI_CRAWL observations that earlier collectors left in the workdir.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__",
             "coverage", "shipgate-workdir", ".vault", ".vite", "playwright-report",
             "test-results", "temp-images"}
SRC_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".py", ".vue", ".svelte", ".cs"}
MINIFIED_RE = re.compile(r"\.(min|bundle|chunk)\.[jt]sx?$")
COMMENT_RE = re.compile(r"/\*.*?\*/|(?<![:\w])//[^\n]*", re.S)

# FIX-LEDGER-HASH-COMMENTS: SA-17 ("a commented-out route is not a route") was only ever
# applied to C-style comments, so a commented-out Flask / FastAPI / Django route was still
# extracted and became a phantom capability the Builder was sent to chase — the exact
# false-positive class SA-17 exists to prevent. Hash-comment languages get their own pass.
# The alternation consumes string literals FIRST so a '#' inside a string (a URL fragment,
# a colour, an f-string) is never mistaken for a comment.
_HASH_COMMENT_RE = re.compile(
    r"(?s)(?P<s>"
    r"'''.*?'''"
    r'|""".*?"""'
    r"|'(?:\\.|[^'\\\n])*'"
    r'|"(?:\\.|[^"\\\n])*"'
    r")|(?P<c>\#[^\n]*)"
)
_HASH_SUFFIXES = (".py", ".pyi", ".rb", ".sh", ".bash", ".yml", ".yaml", ".toml", ".cfg")

TEST_RE = re.compile(r"(^|/)(__tests__|tests?)/|\.(test|spec)\.[jt]sx?$")
FRONTEND_ROOTS = ("client/", "web/", "frontend/", "app/src/pages", "app/src/components")

ROUTE_RE = re.compile(
    r"""\b(?P<recv>[A-Za-z_$][\w$]*)\s*\.\s*(?P<method>get|post|put|delete|patch|options|head)"""
    r"""\s*\(\s*(?P<q>['"`])(?P<path>[^'"`]*)(?P=q)(?P<rest>\s*,)?""")
PY_ROUTE_PATTERNS = [
    (r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"](?:.*?methods\s*=\s*\[([^\]]*)\])?""", "flask"),
    (r"""@\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""", "fastapi"),
    (r"""\bpath\s*\(\s*['"]([^'"]+)['"]""", "django"),
]
NEST_RE = re.compile(r"""@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]?([^'"`\)]*)['"`]?\s*\)""")
DOTNET_HTTP_RE = re.compile(
    r"""\[\s*Http(?P<method>Get|Post|Put|Delete|Patch|Head|Options)\b\s*"""
    r"""(?:\(\s*['"](?P<path>[^'"]*)['"][^)]*\))?\s*\]""")
DOTNET_ROUTE_RE = re.compile(r"""\[\s*Route\s*\(\s*['"](?P<path>[^'"]+)['"]\s*\)\s*\]""")
DOTNET_MINIMAL_RE = re.compile(
    r"""\.\s*Map(?P<method>Get|Post|Put|Delete|Patch)\s*\(\s*['"](?P<path>[^'"]+)['"]""")

# Step 10b: the .NET async surface (not HTTP routes) and the Angular flow surface. These are
# capabilities a live verifier must exercise; an HTTP-only extractor cannot see them.
_DOTNET_ASYNC = [
    (r"\bclass\s+(\w+)\s*:\s*[^\{]*\bI(?:Distributed|Local)EventHandler<", "event-handler"),
    (r"\bclass\s+(\w+)\s*:\s*[^\{]*\bIConsumer<", "broker-consumer"),
    (r"\bRecurringJob\s*\.\s*AddOrUpdate\b()", "recurring-job"),
    (r"\bBackgroundJob\s*\.\s*(?:Enqueue|Schedule)\b()", "fire-and-forget-job"),
    (r"\bclass\s+(\w+)\s*:\s*[^\{]*\b(?:MassTransitStateMachine|ISaga\b|SagaStateMachineInstance)",
     "saga"),
    (r"\bclass\s+(\w+)\s*:\s*[^\{]*\bIBackgroundWorker\b", "background-worker"),
    (r"\b(?:AddDistributedEventOutbox|IEventOutbox|IEventInbox)\b()", "outbox/inbox"),
]
_NG_FLOW = [
    (r"\bcanActivate(?:Child)?\b|\bimplements\s+CanActivate", "route-guard"),
    (r"\bimplements\s+HttpInterceptor\b|\bintercept\s*\(", "http-interceptor"),
    (r"\bcreateEffect\s*\(|\bofType\s*\(", "ngrx-effect"),
    (r"\*abpPermission|\*ngxPermissionsOnly|\[abpFeature\]|\*abpFeature",
     "permission/feature-directive"),
    (r"\bsignalStore\s*\(|\bpatchState\s*\(", "signal-store"),
]

ROUTER_RECV = re.compile(r"^(app|router|server|api|[a-z]\w*Router|_?router\d*)$", re.I)
# A CLIENT receiver is an outbound CALL, not a route DEFINITION. Without this guard every
# Angular HttpClient / axios call that passes a body mints a phantom backend route.
CLIENT_RECV = re.compile(r"^(_?[Hh]ttp(Client|Service)?|axios|fetch)$")
USE_RE = re.compile(
    r"""\b\w+\s*\.\s*use\s*\(\s*['"`](?P<prefix>/[^'"`]*)['"`]\s*,\s*(?P<ident>[A-Za-z_$][\w$]*)""")
IMPORT_RE = re.compile(r"""import\s+(?P<ident>[A-Za-z_$][\w$]*)\s+from\s+['"](?P<mod>[^'"]+)['"]""")
REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<ident>[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?P<mod>[^'"]+)['"]""")
FETCH_RE = re.compile(r"""\bfetch\s*\(\s*(?P<q>['"`])(?P<url>[^'"`]*)(?P=q)""", re.S)
AXIOS_M_RE = re.compile(
    r"""\baxios\s*\.\s*(?P<method>get|post|put|delete|patch)\s*\(\s*['"`](?P<url>[^'"`]*)['"`]""")
ANGULAR_HTTP_RE = re.compile(
    r"""\b(?:this\s*\.\s*)?(?:_?[Hh]ttp(?:Client|Service)?)\s*\.\s*"""
    r"""(?P<method>get|post|put|delete|patch|head|options)\s*(?:<[^>(;{]*>)?\s*"""
    r"""\(\s*(?P<q>['"`])(?P<url>[^'"`]*)(?P=q)""")
METHOD_OPT_RE = re.compile(r"""\bmethod\s*:\s*['"](?P<m>\w+)['"]""", re.I)
ABP_REST_RE = re.compile(r"""\.\s*request\s*(?:<[^>(;]*>)?\s*\(\s*\{""", re.S)
ABP_URL_RE = re.compile(r"""\burl\s*:\s*(['"`])(?P<url>[^'"`]*)\1""")
ABS_URL_RE = re.compile(r"^(https?:)?//", re.I)
BASE_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*"""
    r"""(?:import\.meta\.env\.\w+|process\.env\.\w+)\s*(?:\?\?|\|\|)\s*['"](?P<url>[^'"]+)['"]""")

# The mock policy (v3.8 POINT 3). A test that mocks dependency X yields NO evidence about X.
_JS_MOCK_RE = re.compile(
    r"""(?:jest|vi)\.mock\(\s*['"`]([^'"`]+)['"`]"""
    r"""|\bnock\(\s*['"`]([^'"`]+)['"`]"""
    r"""|import\s+.*\bfrom\s+['"`](msw[^'"`]*)['"`]""", re.I)
_PY_MOCK_RE = re.compile(
    r"""@(?:mock\.)?patch\(\s*['"]([^'"]+)['"]"""
    r"""|\bmocker\.patch\(\s*['"]([^'"]+)['"]"""
    r"""|\bresponses\.add\(""", re.I)
_TEST_FILE_RE = re.compile(r"(\.spec\.|\.test\.|(^|/)test_|/tests?/|conftest\.py$)")


# --- primitives ---------------------------------------------------------------------------

def is_minified(path):
    """SA-02: minified bundles are valid JS and match the route patterns prolifically
    (Map.get, cache lookups), so they flood the ledger with phantom routes."""
    if MINIFIED_RE.search(path.name):
        return True
    try:
        head = path.read_text(errors="ignore")[:8000]
    except Exception:
        return True
    if not head:
        return False
    return max((len(l) for l in head.splitlines()), default=0) > 2000


def _blank(text):
    """Replace every character except newlines with a space, so line numbers stay accurate."""
    return re.sub(r"[^\n]", " ", text)


def strip_hash_comments(text):
    """Blank `#` comments while leaving string literals intact."""
    def repl(m):
        if m.group("s") is not None:
            return m.group("s")
        return _blank(m.group("c"))
    return _HASH_COMMENT_RE.sub(repl, text)


def strip_comments(text, path=None):
    """SA-17: a commented-out route is not a route. Newlines survive so lines stay accurate.

    C-style comments are always stripped. Hash comments are stripped only for the languages
    that use them, selected by file suffix, so a `#` inside a JS template literal or a CSS
    colour is never touched.
    """
    out = COMMENT_RE.sub(lambda m: _blank(m.group(0)), text)
    if path is not None and str(path).lower().endswith(_HASH_SUFFIXES):
        out = strip_hash_comments(out)
    return out


def norm_path(p):
    p = re.sub(r"[?#].*$", "", (p or "").strip())
    p = re.sub(r"^https?://[^/]+", "", p) or "/"
    p = re.sub(r"\$\{[^}]+\}|:\w+|<[^>]+>|\{[^}]+\}", "{param}", p)
    p = re.sub(r"/\d+(/|$)", r"/{param}\1", p)
    return ("/" + p.strip("/")).rstrip("/") or "/"


def join(prefix, rel):
    a, b = (prefix or "").rstrip("/"), (rel or "").strip()
    if b in ("", "/"):
        return a or "/"
    return norm_path(a + "/" + b.lstrip("/"))


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def walk(repo):
    for f in sorted(repo.rglob("*")):
        if not f.is_file() or f.suffix not in SRC_EXT:
            continue
        try:
            rel = f.relative_to(repo)
        except ValueError:
            continue
        if set(rel.parts) & SKIP_DIRS:
            continue
        if is_minified(f):
            continue
        yield f, rel.as_posix()


def options_blob(text, start):
    """Balanced-brace scan for fetch's 2nd argument.

    A regex cannot do this: real option objects nest arbitrarily
    (`body: JSON.stringify({ ...(x && { y }) })`), and a depth-limited pattern silently
    falls through to method=GET — a false 'method mismatch' finding, i.e. exactly the
    false-positive class this gate exists to prevent. SA-03: the URL argument may itself be
    an expression, so skip to the first TOP-LEVEL comma rather than demanding one.
    """
    i, n = start, len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return ""
            depth -= 1
        elif ch == "," and depth == 0:
            break
        elif ch in "\"'`":
            q, i = ch, i + 1
            while i < n and text[i] != q:
                i += 2 if text[i] == "\\" else 1
        i += 1
    if i >= n or text[i] != ",":
        return ""
    i += 1
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] != "{":
        return ""
    depth, j = 0, i
    while j < n:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return ""


def resolve_bases(text):
    """name -> path-only base (SA-14: `API_URL` -> `/api`) from env-with-fallback decls."""
    out = {}
    for m in BASE_RE.finditer(text):
        out[m.group("name")] = re.sub(r"^https?://[^/]+", "", m.group("url")).rstrip("/")
    return out


def apply_base(url, bases):
    m = re.match(r"^\$\{(\w+)\}(?P<rest>.*)$", url or "")
    if m and m.group(1) in bases:
        return bases[m.group(1)] + m.group("rest"), True
    return url, False


def build_mounts(repo, files):
    """module-rel-path -> [prefixes]. Follows `app.use('<p>', ident)` plus ident's import."""
    mounts = {}
    known = {rel for _, rel in files}
    for f, rel in files:
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if ".use(" not in text:
            continue
        idents = {}
        for m in list(IMPORT_RE.finditer(text)) + list(REQUIRE_RE.finditer(text)):
            idents[m.group("ident")] = m.group("mod")
        for m in USE_RE.finditer(text):
            ident = m.group("ident")
            mod = idents.get(ident)
            if not mod or not mod.startswith("."):
                # Same-file mount: `const router = express.Router(); app.use('/api', router)`.
                # Only following imported routers left the single-file case producing
                # unmounted router-relative paths.
                if re.search(rf"\b{re.escape(ident)}\s*=\s*(?:express\.)?Router\s*\(", text):
                    # Keyed by (file, receiver): the prefix belongs to THAT router only.
                    # Applying it file-wide invented routes that do not exist.
                    mounts.setdefault((rel, ident), []).append(m.group("prefix"))
                continue
            target = (f.parent / mod).resolve()
            for cand in (target, target.with_suffix(".ts"), target.with_suffix(".js"),
                         target / "index.ts", target / "index.js"):
                try:
                    key = cand.relative_to(repo).as_posix()
                except ValueError:
                    continue
                if cand.exists() or key in known:
                    mounts.setdefault(key, []).append(m.group("prefix"))
                    break
    return mounts


def detect_mocks(repo):
    """Module/host tokens the test suite mocks. Best-effort and deliberately conservative."""
    mocked = set()
    for f in sorted(Path(repo).rglob("*")):
        if not f.is_file() or f.suffix.lower() not in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".py"):
            continue
        try:
            rel = f.relative_to(repo)
        except ValueError:
            continue
        if set(rel.parts) & SKIP_DIRS:
            continue
        if not _TEST_FILE_RE.search(rel.as_posix()):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        rx = _PY_MOCK_RE if f.suffix.lower() == ".py" else _JS_MOCK_RE
        for m in rx.finditer(text):
            tok = next((g for g in m.groups() if g), None)
            mocked.add(tok if tok else "<signature-mock>")
    return mocked


def path_is_mocked(path, mocked):
    """Loose on purpose: over-flagging a mocked dependency only ever demands MORE real
    evidence, it never manufactures any."""
    if not path:
        return None
    p = path.lower()
    for tok in mocked:
        if tok == "<signature-mock>":
            continue
        t = tok.lower()
        if t and (t in p or p in t or t.split("/")[-1] in p):
            return tok
    return None


# --- extraction ----------------------------------------------------------------------------

def extract_capabilities(repo):
    """The v3.8 `extract()` body, returning a dict instead of writing a file.

    Shared with the runtime probe so both read exactly the same declared surface.
    """
    repo = Path(repo).resolve()
    files = list(walk(repo))
    mounts = build_mounts(repo, files)

    routes, calls, external = [], [], []
    dotnet_async, ef_smells, ng_flows = [], [], []
    skipped_tests = 0

    for f, rel in files:
        try:
            raw = f.read_text(errors="ignore")
        except Exception:
            continue
        text = strip_comments(raw, rel)
        is_test = bool(TEST_RE.search(rel))
        if is_test:
            skipped_tests += 1

        if not is_test and f.suffix == ".cs":
            for pat, kind in _DOTNET_ASYNC:
                for mm in re.finditer(pat, text):
                    dotnet_async.append({
                        "kind": kind, "symbol": (mm.group(1) if mm.groups() else "") or "",
                        "file": rel, "line": line_of(text, mm.start())})
            for mm in re.finditer(r"\b(FromSqlRaw|ExecuteSqlRaw)\s*\(\s*\$", text):
                ef_smells.append({"smell": "interpolated-raw-sql", "file": rel,
                                  "line": line_of(text, mm.start())})
            for mm in re.finditer(r"\.SaveChanges(?:Async)?\s*\(", text):
                ef_smells.append({"smell": "savechanges (verify inside a UoW/transaction)",
                                  "file": rel, "line": line_of(text, mm.start())})
        if not is_test and f.suffix in {".ts", ".tsx"}:
            for pat, kind in _NG_FLOW:
                for mm in re.finditer(pat, text):
                    ng_flows.append({"kind": kind, "file": rel, "line": line_of(text, mm.start())})

        if not is_test and f.suffix == ".py":
            # The Express-shaped v2 rewrite once returned ZERO routes for a Flask app; a whole
            # framework family going dark is worse than a phantom, because nothing downstream
            # looks suspicious.
            for pat, kind in PY_ROUTE_PATTERNS:
                for m in re.finditer(pat, text):
                    g = m.groups()
                    ln = line_of(text, m.start())
                    if kind == "flask":
                        path, methods = g[0], (g[1] or "GET")
                        for meth in (re.findall(r"[A-Z]+", methods.upper()) or ["GET"]):
                            routes.append({"method": meth, "path": norm_path(path),
                                           "declared_as": norm_path(path), "mount": "(decorator)",
                                           "file": rel, "line": ln})
                    elif kind == "django":
                        routes.append({"method": "ANY", "path": norm_path(g[0]),
                                       "declared_as": norm_path(g[0]), "mount": "(urlconf)",
                                       "file": rel, "line": ln})
                    else:
                        routes.append({"method": g[0].upper(), "path": norm_path(g[1]),
                                       "declared_as": norm_path(g[1]), "mount": "(decorator)",
                                       "file": rel, "line": ln})

        if not is_test and f.suffix == ".cs":
            for m in DOTNET_HTTP_RE.finditer(text):
                p = m.group("path") or ""
                routes.append({"method": m.group("method").upper(),
                               "path": norm_path("/" + p.lstrip("/")) if p else "(controller-relative)",
                               "declared_as": p or "(none)",
                               "mount": "(dotnet-attr: verify controller prefix)",
                               "file": rel, "line": line_of(text, m.start())})
            for m in DOTNET_ROUTE_RE.finditer(text):
                p = m.group("path")
                routes.append({"method": "ANY", "path": norm_path("/" + p.lstrip("/")),
                               "declared_as": p, "mount": "(dotnet-route: verify controller prefix)",
                               "file": rel, "line": line_of(text, m.start())})
            for m in DOTNET_MINIMAL_RE.finditer(text):
                p = m.group("path")
                routes.append({"method": m.group("method").upper(),
                               "path": norm_path("/" + p.lstrip("/")),
                               "declared_as": p, "mount": "(minimal-api)",
                               "file": rel, "line": line_of(text, m.start())})

        if not is_test and f.suffix not in (".cs", ".py"):
            for m in ROUTE_RE.finditer(text):
                recv, path, meth = m.group("recv"), m.group("path"), m.group("method").upper()
                if CLIENT_RECV.match(recv):
                    continue
                # SA-11: require a router-ish receiver OR (path-shaped + a handler argument).
                if not (ROUTER_RECV.match(recv) or (path.startswith("/") and m.group("rest"))):
                    continue
                if not path.startswith("/"):
                    continue
                rel_path = norm_path(path)
                prefixes = mounts.get((rel, recv)) or mounts.get(rel, [])
                for pre in (prefixes or [""]):
                    routes.append({"method": meth,
                                   "path": join(pre, rel_path) if pre else rel_path,
                                   "declared_as": rel_path, "mount": pre or "(unmounted)",
                                   "file": rel, "line": line_of(text, m.start())})
            for m in NEST_RE.finditer(text):
                p = (m.group(2) or "").strip()
                routes.append({"method": m.group(1).upper(),
                               "path": norm_path("/" + p.lstrip("/")) if p else "(controller-relative)",
                               "declared_as": p or "(none)",
                               "mount": "(nest-decorator: verify @Controller prefix)",
                               "file": rel, "line": line_of(text, m.start())})

        if f.suffix in {".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".mjs"}:
            bases = resolve_bases(text)

            def record(method, raw_url, idx):
                url, _based = apply_base(raw_url, bases)
                rec = {"method": method, "path": norm_path(url), "raw_url": raw_url,
                       "file": rel, "line": line_of(text, idx)}
                # SA-12 (revised): classify by URL SHAPE first. A root-relative URL targets
                # this app wherever the file lives; an absolute origin or an unresolved
                # ${VAR} base is third-party. Directory is only a tiebreaker — requiring a
                # client/ prefix broke flat repos.
                internal = url.startswith("/") and not ABS_URL_RE.match(url)
                (calls if internal else external).append(rec)

            for m in FETCH_RE.finditer(text):
                opts = options_blob(text, m.end())
                mm = METHOD_OPT_RE.search(opts)
                record(mm.group("m").upper() if mm else "GET", m.group("url"), m.start())
            for m in AXIOS_M_RE.finditer(text):
                record(m.group("method").upper(), m.group("url"), m.start())
            for m in ANGULAR_HTTP_RE.finditer(text):
                record(m.group("method").upper(), m.group("url"), m.start())
            for m in ABP_REST_RE.finditer(text):
                obj = text[m.end():m.end() + 400]   # bounded window; survives ${...} in the url
                um = ABP_URL_RE.search(obj)
                if not um:
                    continue
                mm = METHOD_OPT_RE.search(obj)
                record(mm.group("m").upper() if mm else "GET", um.group("url"), m.start())

    def dedup(xs, keys):
        seen, out = set(), []
        for x in xs:
            k = tuple(x[j] for j in keys)
            if k not in seen:
                seen.add(k)
                out.append(x)
        return out

    return {
        "backend_routes": dedup(routes, ("method", "path")),
        "frontend_calls": dedup(calls, ("method", "path")),
        "external_calls": dedup(external, ("method", "path")),
        "async_surface": dotnet_async,
        "data_smells": ef_smells,
        "flow_surface": ng_flows,
        "mounts": mounts,
        "filesScanned": len(files),
        "testFilesSkipped": skipped_tests,
    }


# --- collector -----------------------------------------------------------------------------

_STATUSES = ("EVIDENCED", "WIRING_GAP", "UNVERIFIED", "MOCKED", "NOT_APPLICABLE")


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


class LedgerCollector(Collector):
    """Extract every declared capability and merge the runtime observations onto it.

    Run order matters: this collector reads `<workdir>/probe.json` and
    `<workdir>/interactions.json`, so it must run AFTER `RuntimeProbeCollector` and
    `UiCrawlCollector`. If neither is present every capability stays UNVERIFIED, which the
    `ledger_no_wiring_gaps` evaluator fails — the honest, fail-closed result.
    """

    kind = EvidenceKind.LEDGER
    name = "ledger"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"

        ex = extract_capabilities(root)
        mocked = detect_mocks(root)

        probe = ctx.option("probe_payload") or _load_json(workdir / "probe.json")
        crawl = ctx.option("interactions") or _load_json(workdir / "interactions.json")

        # (method, path) -> probe route record
        pmap = {}
        if isinstance(probe, dict):
            for r in probe.get("routes") or []:
                if isinstance(r, dict):
                    pmap[(str(r.get("method", "")).upper(), norm_path(r.get("path")))] = r

        entries, uncovered = [], []
        mock_target = bool(ctx.option("mock_target"))

        # --- backend routes -----------------------------------------------------------------
        for r in ex["backend_routes"]:
            hit = pmap.get((r["method"], r["path"]))
            if hit is None and r["method"] == "ANY":
                hit = pmap.get(("GET", r["path"]))
            status, detail = "UNVERIFIED", "no runtime observation for this route"
            if hit is not None:
                judgment = str(hit.get("judgment", "")).upper()
                if judgment == "SERVED":
                    status = "MOCKED" if mock_target else "EVIDENCED"
                    detail = f"{hit.get('status')} — {hit.get('detail', '')}"
                elif judgment == "ABSENT":
                    status, detail = "WIRING_GAP", f"{hit.get('status')} — {hit.get('detail', '')}"
                elif judgment == "MOCKED":
                    status, detail = "MOCKED", f"{hit.get('status')} — {hit.get('detail', '')}"
                else:
                    # FIX-LEDGER-INCONCLUSIVE-IS-UNVERIFIED: an INCONCLUSIVE probe is not a
                    # gap and is certainly not evidence; it stays UNVERIFIED so the ledger
                    # check fails closed rather than reporting either a clean route or a
                    # phantom bug for the Builder to chase.
                    status = "UNVERIFIED"
                    detail = f"probe inconclusive: {hit.get('detail', '')}"
            tok = path_is_mocked(r["path"], mocked)
            if tok:
                # v3.8 POINT 3: annotation only. A mocked dependency NEVER upgrades a status,
                # and (FIX-LEDGER-MOCK-NOT-A-PASS) it never downgrades an unobserved
                # capability to MOCKED either — MOCKED passes the ledger check upstream, so
                # using it to describe something we could not observe would be fail-open.
                detail += f" | mocked dependency {tok!r}: a test that mocks X is no evidence about X"
            entries.append({
                "id": f"route:{r['method']}:{r['path']}",
                "kind": "backend-route",
                "status": status,
                "method": r["method"],
                "path": r["path"],
                "file": r["file"],
                "line": int(r["line"]),
                "detail": detail,
            })

        # --- frontend call sites (the contract diff) -----------------------------------------
        live = {(e["method"], e["path"]) for e in entries if e["status"] == "EVIDENCED"}
        live_paths = {p for _, p in live}
        for c in ex["frontend_calls"]:
            key = (c["method"], c["path"])
            hit = pmap.get(key)
            if key in live:
                status, detail = "EVIDENCED", "matches a live-evidenced backend route"
            elif hit is not None and str(hit.get("judgment", "")).upper() == "SERVED":
                # The prober hit this exact path. The route IS served; what failed is
                # extraction, not wiring. Calling it a WIRING_GAP sends the Builder to fix
                # routing that is already correct and hides a real extractor blind spot.
                status = "EVIDENCED"
                detail = ("served but never extracted as a route — EXTRACTOR BLIND SPOT "
                          "(dynamic registration? unsupported framework?); add it by hand")
            elif pmap:
                near = sorted(p for p in live_paths if p.endswith(c["path"].split("/")[-1]))[:3]
                status = "WIRING_GAP"
                detail = ("the frontend calls a path the live backend did not serve "
                          f"(prefix/version mismatch?); nearest live: {near or '(none)'}")
            else:
                status, detail = "UNVERIFIED", "no runtime observation to reconcile this call against"
            tok = path_is_mocked(c["path"], mocked)
            if tok:
                detail += f" | mocked dependency {tok!r}: a test that mocks X is no evidence about X"
            entries.append({
                "id": f"call:{c['method']}:{c['path']}",
                "kind": "frontend-call",
                "status": status,
                "method": c["method"],
                "path": c["path"],
                "file": c["file"],
                "line": int(c["line"]),
                "detail": detail,
            })

        # --- UI controls, from the crawl ------------------------------------------------------
        if isinstance(crawl, list):
            for i, it in enumerate(crawl):
                if not isinstance(it, dict):
                    continue
                dead = not it.get("fired_network") and not it.get("dom_changed")
                errs = list(it.get("console_errors") or [])
                skipped = it.get("skipped")
                if skipped:
                    status = "UNVERIFIED"
                    detail = f"control not exercised: {skipped}"
                elif dead or errs:
                    status = "WIRING_GAP"
                    detail = "dead control (no network, no DOM change)" if dead else \
                             f"console errors: {'; '.join(str(e)[:120] for e in errs[:3])}"
                else:
                    status = "MOCKED" if mock_target else "EVIDENCED"
                    detail = (f"fired {len(it.get('fired_network') or [])} request(s), "
                              f"dom changed")
                entries.append({
                    "id": f"ui:{it.get('page', '')}:{it.get('selector', i)}",
                    "kind": "ui-control",
                    "status": status,
                    "method": "UI",
                    "path": str(it.get("page") or ""),
                    "file": str(it.get("label") or ""),
                    "line": 0,
                    "detail": detail,
                })

        counts = {s: 0 for s in _STATUSES}
        for e in entries:
            counts[e["status"]] = counts.get(e["status"], 0) + 1

        mounts = sorted(
            [{"module": (k if isinstance(k, str) else f"{k[0]}::{k[1]}"), "prefix": pre}
             for k, v in ex["mounts"].items() for pre in v],
            key=lambda d: (d["module"], d["prefix"]))
        unresolved = [f"{r['method']} {r['path']} ({r['file']}:{r['line']})"
                      for r in ex["backend_routes"] if r["mount"] == "(unmounted)"]

        # FIX-LEDGER-ASYNC-SURFACE-UNCOVERED: v3.8 printed the .NET async / Angular flow
        # inventories as advice and let the run look clean. They are real capabilities that
        # nothing here exercised, so they are declared UNCOVERED, which makes the evidence
        # PARTIAL and fails the ledger check instead of quietly passing it.
        if ex["async_surface"]:
            uncovered.append(f"async-surface: {len(ex['async_surface'])} handler(s)/job(s)/saga(s) "
                             f"not exercised by any runtime observation")
        if ex["flow_surface"]:
            uncovered.append(f"flow-surface: {len(ex['flow_surface'])} guard(s)/interceptor(s)/"
                             f"effect(s) not exercised by any runtime observation")
        if not probe:
            uncovered.append("runtime-probe: no probe observation was available to merge")

        payload = {
            "entries": entries,
            "counts": counts,
            "mounts": mounts,
            "unresolvedMounts": unresolved,
            "asyncSurface": ex["async_surface"],
            "flowSurface": ex["flow_surface"],
            "dataSmells": ex["data_smells"],
            "externalCalls": ex["external_calls"],
            "mockedTokens": sorted(t for t in mocked),
            "extraction": {"filesScanned": ex["filesScanned"],
                           "testFilesSkipped": ex["testFilesSkipped"],
                           "mountsResolved": len(mounts)},
        }
        try:
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "ledger.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass

        note = (f"{len(entries)} capabilities: " +
                ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v))
        if not ex["backend_routes"]:
            # Silence is the dangerous case: an empty ledger satisfies "zero WIRING_GAP"
            # trivially, so a whole framework going unextracted looks like a clean result.
            note += (" | ZERO backend routes extracted — if this repo serves HTTP the "
                     "extractor is blind to its framework; do NOT read the empty ledger as "
                     "evidence")
        return self.collected(ctx, payload, note=note, uncovered=uncovered)
