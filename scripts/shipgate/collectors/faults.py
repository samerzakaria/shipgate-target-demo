"""FAULT_AUDIT + FAIL_FIRST collectors — ACH-style targeted fault injection.

Ported from v3.8 `faultgen.py`. The principle is Meta's ACH: generate realistic faults FIRST,
then require every test to KILL at least one fault before it is admitted as evidence. A test
that has never been seen to fail proves nothing.

Preserved from v3.8, behaviour for behaviour:

  * the OPERATOR SET and its per-language validity table (`OPS`) — a js `if (x)` negation
    reaching a `.py` file produced a SyntaxError, and a syntax error is "killed" by anything
    that merely imports the module, so a suite asserting nothing scored 100%;
  * NON-CODE MASKING with the authoritative parser first and the hand-rolled scanner as the
    fallback (`mask_noncode`): comments, docstrings, regex literals, JSX text and TS
    string-literal types can never host an injection site, because a fault there is
    unkillable and the gate could never converge;
  * MUTATION VALIDITY CHECKING, baseline-relative (`mutation_is_valid`): whatever the operator
    emits must still parse, and a checker that cannot read the CLEAN file abstains instead of
    vetoing — otherwise every JSX/TS repo enumerates zero faults;
  * the `NEEDS_CHECKER` rule: an operator that injects a `return` is only offered when a
    checker actually vetted the mutation;
  * the GIT-CLEAN GUARD (with generated-file tolerance) so reverts are provably clean, the
    `.shipgate-fault` backup/REVERT protocol, and the deterministic ≤2-sites-per-operator cap
    with the coverage-cap disclosure.

FIX-FAULT-ERROR-IS-NOT-DETECTION (the v3.8 defect this file exists to close): v3.8's audit
recorded a hung or crashed fault run in `errored` and ALSO pushed it into `undetected`, and
its callers only ever read one of the two. A run that times out tells you NOTHING about
detection — it is a blind spot, not a kill and not a miss. Here rc 124 (timeout), rc 125
(output limit) and rc 127 (spawn failure) each land in `errored` (and 124 additionally in
`timedOut`), are never counted as detected, and `no_undetected_faults` fails closed on a
non-empty `errored`.

Every process — the target's test command, `node --check`, the TypeScript masker, `git` —
goes through the execution adapter. Nothing here imports `subprocess`.
"""
import ast
import io
import json
import re
import tokenize
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

#: The adapter's own sentinels (execadapter.adapter.RC_*). Duplicated as literals rather than
#: imported so this module's import graph stays free of the execution machinery.
RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127
#: FIX-FAULT-ERROR-IS-NOT-DETECTION: none of these is "the test failed", so none is a kill.
ERROR_RCS = (RC_TIMEOUT, RC_OUTPUT_LIMIT, RC_SPAWN_FAILED)

SKIP = {"node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__",
        "coverage", "tests", "test", "__tests__", "shipgate-workdir", "selftest"}

JS_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
PY_EXT = {".py"}
SRC_EXT = JS_EXT | PY_EXT

#: v3.8 OPS, verbatim. Every operator declares the languages it is VALID for.
OPS = [
    ("prefix",  None,   r"""(['"`])/api/""",                       r"\1/xapi/",   "route prefix broken"),
    ("method",  JS_EXT, r"""\.get\(\s*(['"`]/)""",                 r".post(\1",   "GET swapped to POST"),
    # Indent derived from the matched `except` line, not hardcoded: an `except` inside a class
    # method sits deeper, and a fixed indent produced an IndentationError (a free kill).
    ("swallow", PY_EXT, r"""(?m)^([ \t]*)(except\s+\w*Exception[^\n:]*:)""",
                lambda m: f"{m.group(1)}{m.group(2)}\n{m.group(1)}    return {{'ok': True}}  # FAULT",
                "exception swallowed (py)"),
    ("swallow", JS_EXT, r"""(catch\s*\([^)]*\)\s*\{)""",           r"\1 return undefined; /* FAULT */",
                "error swallowed (js)"),
    ("negate",  JS_EXT, r"""\bif\s*\(\s*(?!FAULT)([a-zA-Z_][\w.]*)\s*\)""", r"if (!\1 /*FAULT*/)",
                "condition negated (js)"),
    # No trailing comment: `if x: return y` is ordinary Python, and appending "# FAULT" after the
    # colon commented out the inline body, leaving an `if` with no body at all.
    ("negate",  PY_EXT, r"""\bif\s+(?!not\b)([a-zA-Z_][\w.]*)\s*:""",       r"if not \1:",
                "condition negated (py)"),
]

#: Operators whose replacement can make a file unloadable depending on where the site sits —
#: the js `swallow` inserts a `return`, illegal at the top level of an ESM module. Offered only
#: when a checker actually VETTED the mutation; abstaining must not mean "assume valid".
NEEDS_CHECKER = {"swallow"}

#: Generated dirs/files a TEST RUN creates — never source. Without this the FIRST audit makes
#: the SECOND refuse "working tree dirty".
_GEN_DIRS = ("shipgate-workdir", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             ".tox", "node_modules", ".next", ".nyc_output", ".gradle", "coverage",
             # scratch the other collectors hand to target runners, which cannot write into
             # the RO-bound workdir (see heldout.SCRATCH_DIR / the cosmic-ray session).
             ".shipgate-heldout")
_GEN_SUFFIX = (".pyc", ".pyo")

BACKUP_SUFFIX = ".shipgate-fault"

#: v3.8 `_jsmask.js`, embedded so the authoritative masker needs no shipped asset. It prints the
#: exact character ranges of every regex/string/template/JSX-text token using the TypeScript
#: compiler API, which resolves regex-vs-division and template nesting grammatically instead of
#: by guesswork.
_JSMASK_SRC = r"""'use strict';
let ts;
try { ts = require('typescript'); } catch (e) { process.stderr.write('no-typescript\n'); process.exit(3); }
const fs = require('fs');
const file = process.argv[2];
const kindArg = (process.argv[3] || 'JS').toUpperCase();
const SK = ts.ScriptKind;
const scriptKind = ({JS: SK.JS, JSX: SK.JSX, TS: SK.TS, TSX: SK.TSX})[kindArg] || SK.JS;
let text;
try { text = fs.readFileSync(file, 'utf8'); } catch (e) { process.stderr.write('read-fail\n'); process.exit(4); }
let sf;
try { sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind); }
catch (e) { process.stderr.write('parse-fail\n'); process.exit(5); }
const K = ts.SyntaxKind;
const spans = [];
function kindOf(node) {
  switch (node.kind) {
    case K.RegularExpressionLiteral: return 'regex';
    case K.StringLiteral: {
      const p = node.parent;
      const isType = p && (p.kind === K.LiteralType || (p.kind === K.PropertySignature && p.name === node));
      return isType ? 'typestr' : 'string';
    }
    case K.NoSubstitutionTemplateLiteral: return 'notmpl';
    case K.TemplateHead:
    case K.TemplateMiddle:
    case K.TemplateTail: return 'tmplstr';
    case K.JsxText: return 'jsxtext';
    default: return null;
  }
}
function visit(node) {
  const k = kindOf(node);
  if (k) { let start; try { start = node.getStart(sf); } catch (e) { start = node.pos; } spans.push([start, node.end, k]); }
  ts.forEachChild(node, visit);
}
try { visit(sf); } catch (e) { process.stderr.write('walk-fail\n'); process.exit(6); }
process.stdout.write(JSON.stringify({ len: text.length, spans: spans }));
"""


# ---------------------------------------------------------------------------------------
# node, through the adapter
# ---------------------------------------------------------------------------------------

class NodeTool:
    """`node` access for the masker and the syntax checker, via `ctx.adapter` only.

    Scratch files are written under the workdir (which the run area's excludes hide from git,
    and which is the only place a contained child can still see) — never /tmp, which bwrap
    replaces with an empty tmpfs.
    """

    def __init__(self, ctx, root, workdir):
        self.ctx = ctx
        self.root = Path(root)
        self.tmp = Path(workdir) / "_faultgen"
        self._available = None
        self._mask_ok = None
        self._masker = None

    def _run(self, argv, timeout):
        try:
            return self.ctx.adapter.run_target(argv=argv, cwd=str(self.root), timeout=timeout)
        except Exception:  # noqa: BLE001 — no boundary / refused = NO SIGNAL, never a verdict
            return None

    def _scratch(self, suffix, text):
        try:
            self.tmp.mkdir(parents=True, exist_ok=True)
            p = self.tmp / f"scratch{suffix or '.js'}"
            with open(p, "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
                fh.write(text)
            return p
        except OSError:
            return None

    @property
    def available(self):
        if self._available is None:
            res = self._run(["node", "--version"], 30)
            self._available = bool(res is not None and res.returncode == 0)
        return self._available

    def check(self, path, text):
        """v3.8 `_js_ok`: True / False / None (no checker available => no signal)."""
        if not self.available:
            return None
        p = self._scratch(Path(path).suffix, text)
        if p is None:
            return None
        res = self._run(["node", "--check", str(p.relative_to(self.root))], 30)
        if res is None or res.returncode in ERROR_RCS:
            return None
        return res.returncode == 0

    def spans(self, path, text):
        """v3.8 `_mask_via_ts`: the TypeScript parser's literal spans, or None to fall back."""
        kind = _ts_kind(path)
        if kind is None or not self.available:
            return None
        if self._mask_ok is None:
            try:
                self.tmp.mkdir(parents=True, exist_ok=True)
                self._masker = self.tmp / "_jsmask.js"
                self._masker.write_text(_JSMASK_SRC)
            except OSError:
                self._mask_ok = False
                return None
            res = self._run(["node", "-e", "require('typescript')"], 30)
            self._mask_ok = bool(res is not None and res.returncode == 0)
        if not self._mask_ok:
            return None
        p = self._scratch(Path(path).suffix, text)
        if p is None:
            return None
        res = self._run(["node", str(self._masker.relative_to(self.root)),
                         str(p.relative_to(self.root)), kind], 30)
        if res is None or res.returncode != 0 or not (res.stdout or "").strip():
            return None
        try:
            data = json.loads(res.stdout)
            spans = data["spans"]
            if int(data.get("len", -1)) != _u16_len(text):
                return None            # offset space disagrees — refuse rather than misalign
            if not text.isascii():
                m = _u16_to_cp(text)
                spans = [[m[int(s)], m[int(e)], k] for s, e, k in spans]
            return spans
        except Exception:  # noqa: BLE001 — malformed spans: fall back, never a worse answer
            return None


def _ts_kind(path):
    s = Path(path).suffix
    if s == ".tsx":
        return "TSX"
    if s in (".ts", ".mts", ".cts"):
        return "TS"
    if s == ".jsx":
        return "JSX"
    if s in (".js", ".mjs", ".cjs"):
        return "JS"
    return None


def _u16_len(text):
    """UTF-16 code-unit length of a Python str (astral code points count as 2)."""
    return sum(2 if ord(c) > 0xFFFF else 1 for c in text)


def _u16_to_cp(text):
    """Map[UTF-16 offset] -> code-point offset. TypeScript reports UTF-16 positions."""
    m = []
    for i, c in enumerate(text):
        m.append(i)
        if ord(c) > 0xFFFF:
            m.append(i)
    m.append(len(text))
    return m


# ---------------------------------------------------------------------------------------
# non-code masking (v3.8 mask_noncode, ported)
# ---------------------------------------------------------------------------------------

def _off(text, lineno, col):
    lines = text.splitlines(keepends=True)
    return sum(len(l) for l in lines[:lineno - 1]) + col


def _apply_spans(path, text, spans):
    n = len(text)
    out = list(text)
    covered = bytearray(n)               # 1 = inside a string/regex/template literal
    _blank_tpl = Path(path).suffix in (".ts", ".tsx", ".mts", ".cts")

    def blank(a, b):
        for i in range(max(0, a), min(n, b)):
            if out[i] != "\n":
                out[i] = " "

    for s, e, kind in spans:
        s, e = int(s), int(e)
        if not (0 <= s <= e <= n):
            # Offset-space disagreement, not something to clamp: clamping a whole-file span
            # would silently wipe every site.
            raise ValueError("span out of range")
        for i in range(s, e):
            covered[i] = 1
        if kind == "regex":
            blank(s, e)                  # no operator may live inside a regex literal
        elif kind == "jsxtext":
            blank(s, e)                  # display text is not code
        elif kind == "typestr":
            blank(s, e)                  # runtime-erased TS type string — an injected fault is unkillable
        elif kind in ("notmpl", "tmplstr") and _blank_tpl:
            blank(s, e)
        # kind == "string": kept intact — real routes live in ' and " strings
    # Comments are not AST nodes; find them only in regions the parser did NOT mark as a
    # literal, so a `//` inside a regex/string/template can never be mistaken for a comment.
    i = 0
    while i < n:
        if covered[i]:
            i += 1
            continue
        if text[i] == "/" and i + 1 < n and text[i + 1] == "/" and not covered[i + 1]:
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if text[i] == "/" and i + 1 < n and text[i + 1] == "*" and not covered[i + 1]:
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def mask_noncode(path, text, node=None):
    """Same-length copy of `text` with COMMENTS, DOCSTRINGS, REGEX and non-code blanked.

    Operators match raw source, so without this `prefix` rewrote `'/api/todos'` inside a
    docstring or a `// client for '/api/data'` comment: a mutation that parses and changes
    nothing executable, which NO test can ever kill — a permanent undetected fault whose
    prescribed remedy is unsatisfiable, and which displaces real sites under the per-file cap.

    Offsets are preserved so match positions still index the original text.
    """
    out = list(text)
    _blank_tpl = Path(path).suffix in (".ts", ".tsx", ".mts", ".cts")

    def blank(a, b):
        for i in range(max(0, a), min(len(out), b)):
            if out[i] != "\n":
                out[i] = " "

    if Path(path).suffix in PY_EXT:
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    blank(_off(text, *tok.start), _off(text, *tok.end))
        except Exception:  # noqa: BLE001
            pass
        try:
            tree = ast.parse(text)
            for n_ in ast.walk(tree):
                if isinstance(n_, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    body = getattr(n_, "body", None) or []
                    if body and isinstance(body[0], ast.Expr) \
                            and isinstance(body[0].value, ast.Constant) \
                            and isinstance(body[0].value.value, str):
                        d = body[0].value
                        blank(_off(text, d.lineno, d.col_offset),
                              _off(text, d.end_lineno, d.end_col_offset))
        except Exception:  # noqa: BLE001
            pass
        return "".join(out)

    # JS/TS: prefer the TypeScript parser's authoritative literal spans; fall back to the
    # scanner below when the toolchain is absent or the spans disagree with the offset space.
    if node is not None:
        spans = node.spans(path, text)
        if spans is not None:
            try:
                return _apply_spans(path, text, spans)
            except Exception:  # noqa: BLE001
                pass

    # --- the hand-rolled fallback scanner, ported verbatim from v3.8 ------------------------
    _RE_PREV = set("(,=:[!&|?{};+-*%^~")
    _RE_KW = ("return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
              "case", "do", "else", "yield", "await")

    def _regex_may_start(k):
        j = k - 1
        while j >= 0 and text[j] in " \t\r\n":
            j -= 1
        if j < 0:
            return True
        # POSTFIX ++/-- is a VALUE, so a following `/` is division, not a regex.
        if text[j] in "+-" and j - 1 >= 0 and text[j - 1] == text[j]:
            return False
        if text[j] == ">":
            # `=>` can be followed by a regex predicate; a bare `>` (JSX `</div>`) cannot.
            return j - 1 >= 0 and text[j - 1] == "="
        if text[j] in _RE_PREV:
            return True
        e = j + 1
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        # `.return` / `.in` are PROPERTY accesses (a value), so a following `/` is division.
        if j >= 0 and text[j] == ".":
            return False
        return text[j + 1:e] in _RE_KW

    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "`":
            # Template literals nest: `${`//`}` desyncs a naive scanner and blanks the rest of
            # the file. Track ${ } depth and the backticks inside it.
            i += 1
            depth = 0
            while i < n:
                ch = text[i]
                if ch == "\\":
                    if _blank_tpl and depth == 0:
                        blank(i, i + 2)
                    i += 2
                    continue
                if depth and ch in "\"'":
                    q = ch
                    i += 1
                    while i < n and text[i] != q:
                        i += 2 if text[i] == "\\" else 1
                    i += 1
                    continue
                if ch == "$" and i + 1 < n and text[i + 1] == "{":
                    depth += 1
                    i += 2
                    continue
                if ch == "{" and depth:
                    depth += 1
                    i += 1
                    continue
                if ch == "}" and depth:
                    depth -= 1
                    i += 1
                    continue
                if ch == "`":
                    if depth == 0:
                        i += 1
                        break
                    i += 1
                    tdepth = 0
                    while i < n:
                        c2 = text[i]
                        if c2 == "\\":
                            i += 2
                            continue
                        if c2 == "$" and i + 1 < n and text[i + 1] == "{":
                            tdepth += 1
                            i += 2
                            continue
                        if c2 == "}" and tdepth:
                            tdepth -= 1
                            i += 1
                            continue
                        if c2 == "`" and tdepth == 0:
                            i += 1
                            break
                        i += 1
                    continue
                if _blank_tpl and depth == 0 and ch != "\n":
                    blank(i, i + 1)
                i += 1
        elif c in "\"'":
            q = c
            i += 1
            while i < n and text[i] != q:
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == "/" and _regex_may_start(i):
            # BLANKED, not merely skipped: an operator matching inside a regex literal breaks
            # the regex, and a broken file is a free kill for any suite that merely imports.
            start = i
            i += 1
            in_class = False
            while i < n and text[i] != "\n":
                ch = text[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    i += 1
                    break
                i += 1
            blank(start, i)
        else:
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------------------
# enumeration / injection (v3.8, ported)
# ---------------------------------------------------------------------------------------

def read_src(f):
    """Read source WITHOUT newline translation and without losing non-UTF8 bytes.

    `read_text` opens in universal-newline mode, so a CRLF file came back LF-only and was
    written back LF: inject+revert silently rewrote the user's line endings and left the run
    area permanently dirty, after which every later audit refused.
    """
    with open(f, "r", encoding="utf-8", errors="surrogateescape", newline="") as fh:
        return fh.read()


def write_src(f, text):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
        fh.write(text)


def _py_ok(path, text):
    try:
        # Compiled as BYTES so CPython honours the file's own coding declaration; a str with
        # surrogates (any non-UTF8 byte under surrogateescape) raises UnicodeEncodeError, not
        # SyntaxError, and used to take the whole audit down over one stray byte.
        data = text.encode("utf-8", "surrogateescape")
        compile(data.lstrip(b"\xef\xbb\xbf"), str(path), "exec")
        return True
    except SyntaxError:
        return False
    except (ValueError, UnicodeError):
        return False


def mutation_is_valid(path, new_text, orig_text=None, node=None):
    """A fault must be a SEMANTIC change, not a syntax error. True / False / None(unknown).

    BASELINE-RELATIVE: judging the mutation alone conflated "this checker cannot parse this
    file" with "my mutation broke it", so `.jsx`, `.tsx`, TS with enums and BOM'd `.py` files
    rejected EVERY mutation and enumerated zero faults.
    """
    suffix = Path(path).suffix
    if suffix in PY_EXT:
        # compile() IS authoritative for .py: a clean file that does not compile is genuinely
        # broken, so every mutation of it is a free kill and the file is skipped entirely.
        if orig_text is not None and not _py_ok(path, orig_text):
            return False
        return _py_ok(path, new_text)
    if suffix in JS_EXT:
        # `node --check` is NOT authoritative here: it cannot parse JSX at all, nor TS
        # enums/namespaces. A clean file it rejects means "no signal", not "the file is broken".
        if node is None:
            return None
        if orig_text is not None and node.check(path, orig_text) is not True:
            return None
        return node.check(path, new_text) is not False
    return True


def apply_op(op, text, start, end):
    """Apply one operator to the single match spanning [start, end)."""
    return text[:start] + re.sub(op[1], op[2], text[start:end]) + text[end:]


def ops_for(path):
    suf = Path(path).suffix
    return [(op, pat, repl, desc) for op, exts, pat, repl, desc in OPS
            if exts is None or suf in exts]


def sources(root):
    for f in sorted(Path(root).rglob("*")):
        if f.is_file() and f.suffix in SRC_EXT and not (set(f.parts) & SKIP) \
                and ".spec." not in f.name and ".test." not in f.name \
                and not f.name.startswith("test_"):
            yield f


def enumerate_faults(root, node=None, max_sites_per_op=2):
    """v3.8 `enumerate_faults`. Returns (faults, skipped) — skips are NAMED, never silent."""
    root = Path(root)
    faults, fid, skipped = [], 0, []
    for f in sources(root):
        try:
            text = read_src(f)
        except OSError as exc:
            skipped.append(f"{f.relative_to(root)} ({type(exc).__name__})")
            continue
        if f.suffix in PY_EXT and not _py_ok(f, text):
            # compile() is authoritative for .py but only for THIS interpreter: a valid 3.12
            # file gated from a 3.11 host also lands here, and a silent drop is invisible
            # coverage loss.
            skipped.append(str(f.relative_to(root)))
            continue
        if f.suffix in JS_EXT:
            try:
                raw = f.read_bytes()
            except OSError:
                raw = b""
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw[:4000]:
                skipped.append(str(f.relative_to(root)) + " (not UTF-8 — likely UTF-16)")
                continue
        masked = mask_noncode(f, text, node)
        for op, pat, repl, desc in ops_for(f):
            # Matched against the MASKED copy so comments and docstrings cannot host a fault;
            # positions still index the original because masking preserves length.
            for m in list(re.finditer(pat, masked))[:max_sites_per_op]:
                mutated = apply_op((op, pat, repl, desc), text, m.start(), m.end())
                if mutated == text:
                    # A MUTATION THAT CHANGES NOTHING IS NOT A FAULT (and used to make `inject`
                    # abort mid-audit with a false "the fault list is stale").
                    continue
                verdict = mutation_is_valid(f, mutated, text, node)
                if verdict is False:
                    continue
                if verdict is None and op in NEEDS_CHECKER:
                    # No checker signal for this file. A structural operator is still safe to
                    # offer; one that injects a `return` is not — unchecked it can produce a
                    # file that fails to load, and an import-only suite scores that as a kill.
                    continue
                faults.append({
                    "id": fid,
                    "op": op,
                    "file": str(f.relative_to(root)),
                    "pos": m.start(),
                    "line": text.count("\n", 0, m.start()) + 1,
                    "desc": desc,
                    "snippet": text[max(0, m.start() - 30):m.start() + 50].replace("\n", "\\n"),
                })
                fid += 1
    return faults, skipped


def inject(root, fault, node=None):
    """Apply one fault, leaving a `<file>.shipgate-fault` backup. Returns (ok, reason)."""
    f = Path(root) / fault["file"]
    try:
        text = read_src(f)
    except OSError as exc:
        return False, f"unreadable: {type(exc).__name__}: {exc}"
    # ops_for, not OPS: picking the first same-named operator regardless of language is how the
    # js negation reached a .py file. inject must resolve the operator as enumerate did.
    cands = [o for o in ops_for(f) if o[0] == fault["op"] and re.search(o[1], text)]
    if not cands:
        return False, (f"no operator {fault['op']!r} applies to {fault['file']} any more "
                       f"(file changed, or the fault list is stale)")
    op = cands[0]
    bak = Path(str(f) + BACKUP_SUFFIX)
    try:
        if not bak.exists():
            write_src(bak, text)
        matches = list(re.finditer(op[1], text))
        target = min(matches, key=lambda m: abs(m.start() - fault["pos"]))
        new = apply_op(op, text, target.start(), target.end())
        if mutation_is_valid(f, new, text, node) is False:
            # Backstop for a stale fault list: never write source that does not parse.
            return False, (f"injecting {fault['op']} into {fault['file']} would produce source "
                           f"that does not parse; a syntax error is a free kill, not a fault")
        write_src(f, new)
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


def revert(root):
    """Restore every backup. Returns (reverted, failures)."""
    n, failures = 0, []
    for bak in sorted(Path(root).rglob("*" + BACKUP_SUFFIX)):
        orig = Path(str(bak)[:-len(BACKUP_SUFFIX)])
        try:
            orig.write_bytes(bak.read_bytes())
            bak.unlink()
            n += 1
        except OSError as exc:
            failures.append(f"{orig}: {type(exc).__name__}: {exc}")
    return n, failures


def git_clean(ctx, root, ignore=_GEN_DIRS):
    """(clean, detail). Clean apart from the gate's own artifacts and test-run junk."""
    try:
        res = ctx.adapter.run_internal(["git", "status", "--porcelain"], cwd=str(root), timeout=60)
    except Exception as exc:  # noqa: BLE001
        return False, f"git status could not be run: {type(exc).__name__}: {exc}"
    if res.returncode != 0:
        return False, f"git status failed (rc={res.returncode}); the run area may not be a git tree"
    lines = [l for l in (res.stdout or "").splitlines() if l.strip()]
    lines = [l for l in lines
             if not any(part in l[3:].split("/") for part in ignore)
             and not l[3:].endswith(_GEN_SUFFIX)]
    return (not lines), "; ".join(lines[:8])


def _run_suite(ctx, root, test_cmd, timeout):
    """Run the target's test command through the adapter. Returns the ExecResult or None."""
    try:
        return ctx.adapter.run_target(command=test_cmd, cwd=str(root), timeout=timeout,
                                      label=f"test: {test_cmd}")
    except Exception:  # noqa: BLE001 — refused/containment failure is an ERROR, never a kill
        return None


def _outcome(res):
    """('detected'|'undetected'|'errored', reason). rc 124/125/127 are blind spots."""
    if res is None:
        return "errored", "the execution adapter refused or failed to run the test command"
    if res.timed_out or res.returncode == RC_TIMEOUT:
        return "errored", "the test run HUNG and was killed; detection is unknown"
    if res.output_truncated or res.returncode == RC_OUTPUT_LIMIT:
        return "errored", "the test run exceeded the output limit and was killed; detection is unknown"
    if res.returncode == RC_SPAWN_FAILED:
        return "errored", "the test command could not be spawned"
    return ("detected" if res.returncode != 0 else "undetected"), f"rc={res.returncode}"


def _test_command(ctx):
    cmd = ctx.option("test_cmd")
    if not cmd:
        commands = ctx.stack.get("commands") if isinstance(ctx.stack, dict) else None
        if isinstance(commands, dict):
            cmd = commands.get("test")
    return (cmd or "").strip()


# ---------------------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------------------

class FaultAuditCollector(Collector):
    """Inject targeted faults one at a time and record which ones the suite fails to notice.

    Options: `test_cmd`, `max_faults` (default 25), `fault_timeout` (default 600),
    `allow_dirty`.
    """

    kind = EvidenceKind.FAULT_AUDIT
    name = "fault-audit"
    version = "4.2.4"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        test_cmd = _test_command(ctx)
        if not test_cmd:
            return self.error(ctx, "no test command is known (option `test_cmd` or STACK "
                                   "`commands.test`); a fault audit without a suite proves nothing")
        timeout = int(ctx.option("fault_timeout", 600) or 600)
        max_faults = int(ctx.option("max_faults", 25) or 25)

        if not ctx.option("allow_dirty"):
            clean, detail = git_clean(ctx, root)
            if not clean:
                return self.error(ctx, "the run area is not clean, so a revert cannot be proved "
                                       f"complete: {detail}")

        node = NodeTool(ctx, root, workdir)
        all_faults, skipped = enumerate_faults(root, node)
        faults = all_faults[:max_faults]
        scope = (f"first {len(faults)} of {len(all_faults)} injectable site(s), deterministic "
                 f"order (sorted path, operator, <=2 sites per operator per file)")

        if not faults:
            # An audit over ZERO faults writes exactly the `undetected: []` a real clean audit
            # writes. Reported as an incomplete observation instead, which fails closed.
            return self.collected(ctx, {
                "total": 0, "detected": 0, "undetected": [], "errored": [], "timedOut": [],
                "operators": [], "scope": scope, "skippedFiles": skipped,
                "candidateCount": len(all_faults), "testCommand": test_cmd,
            }, note="no injectable fault site was found; an audit over zero faults proves nothing",
               uncovered=["fault-injection: no injectable site was found"])

        # --- baseline: the suite must be green on clean code ---------------------------------
        base = _run_suite(ctx, root, test_cmd, timeout)
        kind_, why = _outcome(base)
        if kind_ == "errored":
            return self.error(ctx, f"the test command could not complete on the UNMODIFIED tree "
                                   f"({why}); an audit against a suite that cannot run clean "
                                   f"proves nothing")
        if base.returncode != 0:
            return self.error(ctx, f"the baseline test run FAILS on clean code (rc="
                                   f"{base.returncode}); the suite must be green before faults "
                                   f"can be judged")

        undetected, errored, timed_out, detected = [], [], [], 0
        revert_failures = []
        try:
            for fl in faults:
                ok, reason = inject(root, fl, node)
                if not ok:
                    errored.append({"id": str(fl["id"]), "reason": f"injection failed: {reason}"})
                    revert(root)
                    continue
                res = _run_suite(ctx, root, test_cmd, timeout)
                verdict, why = _outcome(res)
                if verdict == "detected":
                    detected += 1
                elif verdict == "undetected":
                    undetected.append({"id": str(fl["id"]), "file": fl["file"],
                                       "line": int(fl["line"]), "operator": fl["op"]})
                else:
                    # FIX-FAULT-ERROR-IS-NOT-DETECTION: a hung/crashed run is a BLIND SPOT. It
                    # is NOT pushed into `undetected` as well (v3.8 double-counted it), because
                    # a blind spot and a proven miss are different findings with different
                    # remedies.
                    errored.append({"id": str(fl["id"]),
                                    "reason": f"{fl['op']} in {fl['file']}: {why}"})
                    if res is not None and (res.timed_out or res.returncode == RC_TIMEOUT):
                        timed_out.append(str(fl["id"]))
                _n, failures = revert(root)
                revert_failures += failures
        finally:
            # The tree is NEVER left faulted, whatever goes wrong above. A crash between inject
            # and revert is the one failure mode that damages the thing being gated.
            _n, failures = revert(root)
            revert_failures += failures

        payload = {
            "total": len(faults),
            "detected": detected,
            "undetected": undetected,
            "errored": errored,
            "timedOut": timed_out,
            "operators": sorted({f["op"] for f in faults}),
            "scope": scope,
            "candidateCount": len(all_faults),
            "coverageCapped": len(all_faults) > len(faults),
            "skippedFiles": skipped,
            "auditedFiles": sorted({f["file"] for f in faults}),
            "testCommand": test_cmd,
            "faults": [{"id": str(f["id"]), "file": f["file"], "line": int(f["line"]),
                        "operator": f["op"], "description": f["desc"]} for f in faults],
        }
        uncovered = []
        if revert_failures:
            uncovered.append("revert: " + "; ".join(revert_failures[:3]))
        if skipped:
            uncovered.append(f"{len(skipped)} source file(s) could not be read/compiled and "
                             f"contribute NO faults")
        if payload["coverageCapped"]:
            uncovered.append(f"{len(all_faults) - len(faults)} injectable site(s) were not audited")
        try:
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "fault-audit.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass
        note = (f"{detected}/{len(faults)} injected faults detected; {len(undetected)} undetected, "
                f"{len(errored)} errored")
        return self.collected(ctx, payload, note=note, uncovered=uncovered)


class FailFirstCollector(Collector):
    """The fail-first admission protocol: no test is evidence until it has provably failed.

    v3.8's `admit` ran inject -> expect FAIL -> revert -> expect PASS -> N clean re-runs. That
    protocol is preserved for every declared candidate.

    FIX-FAILFIRST-EXECUTED: admission is EXECUTED here, never read. A candidate record supplies
    only (id, cmd, faultId); an `admitted` field in that file is ignored, because a
    self-asserted admission is exactly the claim this collector exists to test.

    FIX-FAILFIRST-DERIVED: when no candidate record exists, admission is DERIVED from the fault
    audit — one entry per injected fault, admitted only when the suite provably failed under
    that fault (and errored/hung runs are NOT admissions). That is weaker than per-test
    admission and says so in `detail`; it is never silently reported as stronger.

    Options: `fail_first_candidates` (list of {id, cmd, faultId}), `flake_runs` (default 1),
    `test_cmd`, `fault_timeout`.
    """

    kind = EvidenceKind.FAIL_FIRST
    name = "fail-first"
    version = "4.2.4"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        candidates = ctx.option("fail_first_candidates")
        if candidates is None:
            candidates = _load_candidates(workdir / "fail-first.json")

        if candidates:
            return self._execute(ctx, root, workdir, candidates)
        return self._derive(ctx, workdir)

    # --- executed admission --------------------------------------------------------------
    def _execute(self, ctx, root, workdir, candidates):
        test_cmd = _test_command(ctx)
        timeout = int(ctx.option("fault_timeout", 600) or 600)
        flake_runs = int(ctx.option("flake_runs", 1) or 1)
        node = NodeTool(ctx, root, workdir)
        all_faults, _skipped = enumerate_faults(root, node)
        by_id = {str(f["id"]): f for f in all_faults}

        tests, admitted_n = [], 0
        try:
            tests, admitted_n = self._admit_all(ctx, root, candidates, by_id, test_cmd,
                                                timeout, flake_runs, node)
        finally:
            # As in the audit: the tree is never left faulted, whatever happens above.
            revert(root)

        payload = {"tests": tests,
                   "counts": {"admitted": admitted_n, "notAdmitted": len(tests) - admitted_n},
                   "source": "executed admission protocol (inject -> FAIL -> revert -> PASS)"}
        return self.collected(ctx, payload,
                              note=f"{admitted_n}/{len(tests)} candidate(s) admitted fail-first")

    def _admit_all(self, ctx, root, candidates, by_id, test_cmd, timeout, flake_runs, node):
        tests, admitted_n = [], 0
        for cand in candidates:
            if not isinstance(cand, dict):
                continue
            tid = str(cand.get("id") or "?")
            cmd = (cand.get("cmd") or test_cmd or "").strip()
            fid = cand.get("faultId")
            fid = str(fid) if fid is not None else None
            runs, admitted, detail = 0, False, ""
            fault = by_id.get(fid) if fid is not None else None
            if not cmd:
                detail = "no test command for this candidate; nothing could be executed"
            elif fault is None:
                detail = (f"fault {fid!r} is not enumerable in this tree, so the candidate cannot "
                          f"be shown to kill anything")
            else:
                ok, reason = inject(root, fault, node)
                if not ok:
                    detail = f"fault {fid} could not be injected: {reason}"
                    revert(root)
                else:
                    res = _run_suite(ctx, root, cmd, timeout)
                    runs += 1
                    verdict, why = _outcome(res)
                    revert(root)
                    if verdict == "errored":
                        detail = (f"the candidate ERRORED under fault {fid} ({why}); a hang is a "
                                  f"blind spot with an extra reason to worry, not an admission")
                    elif verdict == "undetected":
                        detail = (f"the candidate PASSED with fault {fid} injected — it does not "
                                  f"kill it and is vacuous for this fault")
                    else:
                        clean_ok, clean_detail = True, ""
                        for i in range(1 + max(0, flake_runs)):
                            res2 = _run_suite(ctx, root, cmd, timeout)
                            runs += 1
                            v2, why2 = _outcome(res2)
                            # The fault is reverted, so a PASS is rc 0 — which `_outcome`
                            # labels 'undetected' (nothing was there to detect). Anything else
                            # is a failing or unfinished clean run.
                            if v2 != "undetected":
                                clean_ok = False
                                clean_detail = (f"clean run {i + 1} did not pass ({why2}); a test "
                                                f"that fails on clean code is noise, not an oracle")
                                break
                        if clean_ok:
                            admitted = True
                            detail = (f"failed under fault {fid} and passed {1 + max(0, flake_runs)} "
                                      f"clean run(s)")
                        else:
                            detail = clean_detail
            admitted_n += bool(admitted)
            tests.append({"id": tid, "admitted": bool(admitted), "faultId": fid,
                          "runs": int(runs), "detail": detail})
        return tests, admitted_n

    # --- derived admission -----------------------------------------------------------------
    def _derive(self, ctx, workdir):
        audit = ctx.option("fault_audit_payload")
        if not isinstance(audit, dict):
            audit = _load_json(workdir / "fault-audit.json")
        if not isinstance(audit, dict):
            return self.error(ctx, "no fail-first candidates were declared and no fault audit is "
                                   "available to derive admission from; nothing was proved about "
                                   "any test and that is not a pass")
        faults = audit.get("faults")
        if not isinstance(faults, list) or not faults:
            return self.error(ctx, "the fault audit recorded no injected fault, so no test can "
                                   "have been shown to fail first")
        undetected = {str(u.get("id")) for u in (audit.get("undetected") or [])
                      if isinstance(u, dict)}
        errored = {str(e.get("id")) for e in (audit.get("errored") or []) if isinstance(e, dict)}

        tests, admitted_n = [], 0
        for f in faults:
            if not isinstance(f, dict):
                continue
            fid = str(f.get("id"))
            if fid in errored:
                admitted, detail = False, ("the run under this fault errored or hung; detection is "
                                           "unknown, which is not an admission")
            elif fid in undetected:
                admitted, detail = False, ("no test failed when this fault was injected, so no test "
                                           "is evidence for it")
            else:
                admitted, detail = True, ("the suite provably failed when this fault was injected "
                                          "(suite-level admission derived from the fault audit; "
                                          "weaker than per-test admission)")
            admitted_n += bool(admitted)
            tests.append({"id": f"suite-vs-fault:{fid}", "admitted": bool(admitted),
                          "faultId": fid, "runs": 1, "detail": detail})

        payload = {"tests": tests,
                   "counts": {"admitted": admitted_n, "notAdmitted": len(tests) - admitted_n},
                   "source": "derived from the fault audit (suite-level, not per-test)"}
        return self.collected(
            ctx, payload,
            note=f"{admitted_n}/{len(tests)} fault(s) provably killed by the suite",
            uncovered=["per-test admission: no fail-first candidate record was declared, so "
                       "admission is suite-level"])


def _load_json(path):
    try:
        doc = json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None
    return doc


def _load_candidates(path):
    doc = _load_json(path)
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in ("candidates", "tests"):
            v = doc.get(key)
            if isinstance(v, list):
                return v
    return []
