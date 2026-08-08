"""RUNTIME_PROBE collector — is each declared route actually served?

Ported from v3.8 `probe.py`, keeping the parts that made it trustworthy:

  * a no-redirect opener, so a 302 is judged on its OWN status and cannot borrow the
    destination's 200;
  * `normalise_body`, which strips the probed path, the method and hex/canary tokens so two
    404s from the same server compare equal;
  * PER-SCOPE 404 canaries (`/`, `/api`, ...) with `scope_canary`/`unifies`, so a canary can
    never land in a declared `{param}` handler and invert every comparison;
  * catch-all / history-fallback detection;
  * safe-by-default methods: POST/PUT/PATCH/DELETE are not sent unless writes are allowed,
    and never to a non-local target without explicit consent.

FIX-PROBE-CANARY-ONLY (the v3.8 defect this collector exists to close): v3.8's `judge()`
also read the response BODY SHAPE — a 2xx whose body contained `"error":` was demoted, and
several framework 404 pages were promoted. Body shape is not evidence: Fastify answers an
unrouted path with `{"message":"Route GET:/x not found","error":"Not Found"}` and NestJS
with `{"statusCode":404,"message":"Cannot GET /x"}`. Judgment here is decided ONLY by
comparison against the per-scope canary baseline, and anything that comparison cannot decide
is INCONCLUSIVE — which fails closed upstream instead of being counted as served.

HTTP is performed in-process with `urllib` (stdlib). No process is spawned, so the execution
adapter is not involved; the adapter exists for spawning, and a collector must never spawn.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..models.evidence import EvidenceKind
from ..util.hashing import sha256_text
from .base import Collector
from .ledger import extract_capabilities, norm_path

CANARY_LEAF = "/shipgate-canary-4f2a9e-not-a-route"
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
PARAM_RE = re.compile(r"[:{<][A-Za-z_][A-Za-z0-9_]*[}>]?")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A declared route that answers 3xx must be judged on its own status. urllib follows
    redirects by default, so `/api/secret` -> 302 /login was once recorded as a live 200
    serving the login body."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def concretize(path, value):
    return PARAM_RE.sub(str(value), path or "")


def request(method, url, token=None, body=None, timeout=20):
    """(status, body). status 0 means no response at all — never a judgment on its own."""
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return int(r.status), r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read(4000).decode("utf-8", "replace")
        except Exception:
            text = ""
        return int(exc.code), text
    except Exception as exc:  # connection refused, timeout, bad host, ...
        return 0, f"TRANSPORT-ERROR {type(exc).__name__}: {exc}"


def normalise_body(body, path, method):
    """Strip everything request-specific so two 404s from the same server compare equal.

    Framework 404s echo the request: Express `Cannot GET /api/ghost`, Fastify
    `{"message":"Route GET:/api/ghost not found"}`. Stripping only the canary token left the
    baseline as `Cannot GET /` and every probe body as `Cannot GET /api/ghost`, so EVERY
    unrouted path "differed from the baseline" and was judged served.
    """
    s = (body or "")[:600]
    if path:
        # Boundary-aware: a raw substring replace of a short path like "api" mangles ordinary
        # words in the 404 page ("the rapid capital" -> "the rd ctal") and manufactures a
        # spurious difference, i.e. a false "served".
        for form in (re.escape(path), re.escape(path.lstrip("/"))):
            if form:
                s = re.sub(rf"(?<!\w){form}(?!\w)", "", s)
    s = re.sub(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b", "", s, flags=re.I)
    s = re.sub(r"[0-9a-f-]{6,}|shipgate-canary\S*", "", s)
    return re.sub(r"\s+", " ", s).strip()


def unifies(concrete, pattern):
    """Would a request for `concrete` be matched by declared route `pattern`?"""
    cs = [s for s in (concrete or "").split("/") if s]
    ps = [s for s in (pattern or "").split("/") if s]
    if len(cs) != len(ps):
        return False
    return all(seg.startswith("{") or seg == c for c, seg in zip(cs, ps))


def scope_canary(scope, leaf, declared):
    """A scope baseline is meaningful only if its canary is GUARANTEED unrouted.

    `<scope>/<nonsense>` is not: with a declared `/users/{param}` the canary lands in the
    `{param}` HANDLER, so the "unrouted baseline" for that scope becomes a handler 404 and
    BOTH comparisons invert — a real handler 404 reads as a gap and a genuinely unrouted path
    reads as served. Add nonsense segments until nothing declared unifies with it.
    """
    for depth in range(1, 5):
        cand = scope.rstrip("/") + leaf + "".join(f"{leaf}-{i}" for i in range(depth - 1))
        if not any(unifies(cand, d) for d in declared):
            return cand
    return None


def _scope_key(scope):
    return scope or "/"


class RuntimeProbeCollector(Collector):
    """Probe every declared route against a live base URL and judge it against a canary.

    Options: `base_url` (required), `probe_token`, `param_value`, `allow_writes`,
    `allow_nonlocal_writes`, `probe_timeout`, `extra_probes`.
    """

    kind = EvidenceKind.RUNTIME_PROBE
    name = "runtime-probe"
    version = "4.2.4"

    def collect(self, ctx):
        base = (ctx.option("base_url") or "").strip()
        if not base:
            return self.error(ctx, "no base_url option was supplied, so nothing could be probed; "
                                   "a route that was never requested is not a served route")
        base = base.rstrip("/")
        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        timeout = int(ctx.option("probe_timeout", 20) or 20)
        token = ctx.option("probe_token")
        param_value = str(ctx.option("param_value", "1"))

        declared_routes, declared_calls = self._targets(ctx, root, workdir)
        if not declared_routes and not declared_calls:
            return self.error(ctx, "no declared route or call site was extracted, so there was "
                                   "nothing to probe; an empty probe is not a clean probe")

        # --- write safety -------------------------------------------------------------------
        host = (urllib.parse.urlparse(base).hostname or "").lower()
        local = host in LOCAL_HOSTS
        want_writes = bool(ctx.option("allow_writes"))
        writes_ok = want_writes and (local or bool(ctx.option("allow_nonlocal_writes")))
        write_note = ""
        if want_writes and not writes_ok:
            write_note = (f"REFUSED writes to non-local host {host!r} without "
                          f"allow_nonlocal_writes; write methods were not sent")

        # --- canary baselines ----------------------------------------------------------------
        prefixes = set()
        for r in declared_routes + declared_calls:
            seg = (r.get("path") or "").split("/")
            if len(seg) > 1 and seg[1] and "{" not in seg[1]:
                prefixes.add("/" + seg[1])
        patterns = [r.get("path") for r in declared_routes if r.get("path")]
        scopes = [""] + sorted({p for p in prefixes if p and p != "/"}, key=len, reverse=True)

        per_scope, canary_payload, unbaselined = {}, {}, []
        for scope in scopes:
            cpath = CANARY_LEAF if not scope else scope_canary(scope, CANARY_LEAF, patterns)
            if cpath is None:
                unbaselined.append(scope)
                continue
            methods = ("GET", "POST") if writes_ok else ("GET",)
            pm = {}
            for meth in ("GET", "POST"):
                if meth in methods:
                    # A POST — even to a nonsense canary — can hit a wildcard/catch-all/audit
                    # handler and cause a side effect. Only sent when writes are authorised.
                    st, bd = request(meth, base + cpath, timeout=timeout)
                    sig = normalise_body(bd, cpath, meth)
                    pm[meth] = {"status": st, "sig": sig, "digest": sha256_text(sig),
                                "catch_all": 200 <= st < 300, "measured": st != 0}
                else:
                    pm[meth] = {"status": None, "sig": None, "digest": "",
                                "catch_all": False, "measured": False,
                                "skipped": "unsafe-write"}
            per_scope[scope] = pm
            canary_payload[_scope_key(scope)] = {
                "status": int(pm["GET"]["status"] or 0),
                "bodyDigest": pm["GET"]["digest"] or "",
            }

        root_base = (per_scope.get("") or {}).get("GET") or {}
        established = bool(root_base.get("measured"))
        canary = {
            "established": established,
            "perScope": canary_payload,
            "method": "GET+POST" if writes_ok else "GET",
        }

        # --- probe every declared target -------------------------------------------------------
        targets = [(r["method"], r["path"], None) for r in declared_routes]
        # Every distinct frontend call-site path too: this is what catches prefix mismatches.
        targets += [((c.get("method") or "GET").replace("?", "") or "GET", c["path"], None)
                    for c in declared_calls]
        extra = ctx.option("extra_probes") or []
        if isinstance(extra, list):
            targets += [(e.get("method", "GET"), e.get("path", "/"), e.get("body"))
                        for e in extra if isinstance(e, dict)]

        seen, routes, writes_attempted = set(), [], False
        for method, path, body in targets:
            method = "GET" if method in ("ANY", "GET?") else str(method).upper()
            key = (method, path)
            if key in seen:
                continue
            seen.add(key)
            rid = f"{method} {path}"
            concrete = concretize(path, param_value)
            url = base + concrete

            if method in WRITE_METHODS and not writes_ok:
                routes.append({
                    "id": rid, "method": method, "path": path, "status": 0,
                    "judgment": "INCONCLUSIVE",
                    "detail": "write method not sent (set allow_writes against a disposable "
                              "target to probe it); a route that was never requested is not "
                              "a served route" + (f" — {write_note}" if write_note else ""),
                })
                continue
            if method in WRITE_METHODS:
                writes_attempted = True

            status, text = request(method, url, token, body, timeout=timeout)
            judgment, detail = self._judge(status, text, per_scope, concrete, method)
            routes.append({"id": rid, "method": method, "path": path, "status": int(status),
                           "judgment": judgment, "detail": detail})

        counts = {"SERVED": 0, "ABSENT": 0, "MOCKED": 0, "INCONCLUSIVE": 0}
        for r in routes:
            counts[r["judgment"]] = counts.get(r["judgment"], 0) + 1
        counts["total"] = len(routes)

        payload = {
            "baseUrl": base,
            "canary": canary,
            "routes": routes,
            "counts": counts,
            "writesAttempted": writes_attempted,
            "catchAll": bool(root_base.get("catch_all")),
            "unbaselinedScopes": sorted(unbaselined),
            "writePolicy": write_note or ("writes enabled" if writes_ok else
                                          "writes disabled (safe default)"),
        }
        try:
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "probe.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass

        uncovered = []
        if not established:
            uncovered.append("canary: no 404 baseline could be measured at the root scope")
        if unbaselined:
            uncovered.append("canary: no guaranteed-unrouted canary exists for scope(s) "
                             + ", ".join(sorted(unbaselined)))
        if counts["INCONCLUSIVE"]:
            uncovered.append(f"{counts['INCONCLUSIVE']} route(s) inconclusive")

        if not established:
            # No baseline means 'served' cannot be told apart from 'framework 404'. Report the
            # observation, but as ERROR: a payload of judgments built on no baseline would look
            # like evidence and is not.
            return self.error(ctx, "no 404 canary baseline could be established against "
                                   f"{base}; serving cannot be distinguished from a framework "
                                   "404, so no route judgment here is evidence", payload)
        return self.collected(
            ctx, payload,
            note=f"{len(routes)} routes probed against {base}: " +
                 ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v),
            uncovered=uncovered)

    # --- targets ---------------------------------------------------------------------------
    def _targets(self, ctx, root, workdir):
        """Declared routes + frontend call sites, from the ledger extraction."""
        routes = ctx.option("routes")
        calls = ctx.option("calls")
        if isinstance(routes, list):
            return ([r for r in routes if isinstance(r, dict) and r.get("path")],
                    [c for c in (calls or []) if isinstance(c, dict) and c.get("path")])
        ex = extract_capabilities(root)
        return ex["backend_routes"], ex["frontend_calls"]

    # --- judgment ----------------------------------------------------------------------------
    def _judge(self, status, body, per_scope, path, method):
        """SERVED / ABSENT / MOCKED / INCONCLUSIVE, from the canary baseline ALONE.

        FIX-PROBE-CANARY-ONLY: no body-shape or keyword heuristic participates. The only
        body comparison performed is equality against the canary's own normalised body, which
        is a measurement of THIS server, not a guess about what an error looks like.
        """
        if status == 0:
            return "INCONCLUSIVE", "no response from the server (transport error)"

        mu = (method or "GET").upper()
        # Baseline must match the METHOD class: a history-fallback SPA catches only GET, so an
        # unrouted DELETE still gets the framework 404 — comparing it against the GET
        # (catch-all) baseline would read that 404 as handler proof.
        pm = None
        for s in sorted(per_scope, key=len, reverse=True):
            if s and (path or "").startswith(s):
                pm = per_scope[s]
                break
        if pm is None:
            pm = per_scope.get("") or {}
        base = pm.get(mu) or pm.get("GET" if mu == "GET" else "POST") or {}
        if not base.get("measured"):
            return ("INCONCLUSIVE",
                    f"no canary baseline was measured for {mu} in this scope, so a {status} "
                    f"cannot be told apart from this server's unrouted-path response")

        bstatus = base.get("status")
        sig = normalise_body(body, path, method)

        if base.get("catch_all"):
            # The server answers unrouted paths with 2xx (SPA history fallback / JSON
            # catch-all). A 2xx therefore proves nothing unless the body differs from the
            # catch-all's own body; and a 404 can only have come from a handler.
            if 200 <= status < 300:
                if sig == (base.get("sig") or ""):
                    return ("ABSENT",
                            f"{status} but the body is byte-identical to the catch-all "
                            f"response for a path that certainly does not exist")
                return "SERVED", f"{status} with a body distinct from the catch-all response"
            if status == 404:
                return ("SERVED",
                        f"404 from a handler — unrouted paths on this server answer "
                        f"{bstatus}, so the router did match")
            if status >= 500:
                return "INCONCLUSIVE", f"server error {status} — the route may exist and be broken"
            return "SERVED", f"{status} differs from the catch-all baseline {bstatus}"

        if status == bstatus and status != 404:
            # The canary — a path that certainly does not exist — got this same status. A
            # blanket auth wall answers 401 to everything, so "enforcing something" proves
            # nothing about whether THIS route exists.
            # FIX-PROBE-WALL-IS-INCONCLUSIVE: v3.8 recorded this as not-ok, which the ledger
            # then read as a WIRING_GAP and sent the Builder to fix a route that may be fine.
            # It is undecidable, not absent.
            return ("INCONCLUSIVE",
                    f"{status} matches the response to a nonexistent path (blanket {status} "
                    f"wall); supply probe_token or a route-specific credential")

        if status == 404:
            if bstatus not in (None, 0, 404):
                return ("SERVED",
                        f"404 from a handler — unrouted paths on this server answer {bstatus}, "
                        f"so the router did match")
            if sig and sig != (base.get("sig") or ""):
                return "SERVED", "404 whose body differs from this server's unrouted-path baseline"
            return "ABSENT", "404 identical to the unrouted-path baseline — route not served"

        if status == 405:
            # The path may exist under another method, but THIS declared method is not served.
            return "ABSENT", "405 — this method is not served at this path"

        if 300 <= status < 400:
            # A 3xx means the route did NOT serve its own content; the destination's 200 must
            # not be borrowed as this route's evidence.
            # FIX-PROBE-REDIRECT-IS-INCONCLUSIVE: v3.8 recorded not-ok, which downstream read
            # as "not served". A redirect is undecidable — an auth wall redirect and a
            # swallowed gap look identical from here.
            return ("INCONCLUSIVE",
                    f"{status} redirect — the route did not serve its own content (auth wall "
                    f"or silent redirect), so this is neither proof nor disproof")

        if status >= 500:
            return "INCONCLUSIVE", f"server error {status} — the route may exist and be broken"

        return "SERVED", f"{status}, distinct from the unrouted-path baseline {bstatus}"
