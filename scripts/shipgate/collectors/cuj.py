"""CUJ collector — did each Critical User Journey actually complete?

Ported from v3.8 `synthetic.py` (the journey prober) plus the CUJ half of v3.8 `ledger.py`
(journeys declared by a ledger entry flagged `"cuj": true`). What is preserved:

  * NO REDIRECTS ARE FOLLOWED: a 302 to /login is the journey NOT completing. urllib follows
    redirects by default, and a redirect judged as "served" once hid an auth wall;
  * "the server answered" is NOT "the journey completed": a bare probe requires a 2xx unless
    the journey declares an explicit `expect_status` contract (an int or a list), so a dead
    login answering 404/401/403/405 can no longer pass;
  * a journey that needs a scripted flow (form login, OAuth dance) is beyond a bare HTTP
    probe and is driven by its declared command, whose exit code is the verdict;
  * an EMPTY journey set is refused rather than reported green — `cuj_evidenced` turns an
    empty list into EVD_INCOMPLETE.

FIX-CUJ-MOCK-IS-DECLARED: a journey evidenced against a mock sets `mocked: true`, which
upstream REFUSES (SEM_CUJ_DOWNGRADE_REFUSED). v3.8's synthetic probe had no notion of a mock
at all, so a journey answered by a stub server was indistinguishable from a real one. Mocking
is picked up from the journey's own declaration, from the run's `mock_target` option, and from
a RUNTIME_PROBE judgment of MOCKED.

FIX-CUJ-ERROR-IS-NOT-A-VERDICT: a scripted journey whose command hung, overflowed its output
or could not be spawned is `ERROR`, never `NOT_EVIDENCED` and certainly never `EVIDENCED` — a
journey whose outcome is unknown must not be reported as a proven defect or a proven success.

The HTTP probing is done in-process with `urllib` (stdlib); scripted journeys go through
`ctx.adapter.run_target`. Nothing here imports `subprocess`.
"""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127
ERROR_RCS = (RC_TIMEOUT, RC_OUTPUT_LIMIT, RC_SPAWN_FAILED)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 302 to /login is the journey NOT completing; judge the response on its own status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_probe(base, method, path, timeout=15):
    """(status|None, ms, error). status None means no response at all."""
    url = base.rstrip("/") + (path or "")
    verb = method if method not in ("ANY", "GET?", "") else "GET"
    req = urllib.request.Request(url, method=verb, headers={"Accept": "application/json"})
    t0 = time.time()
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return int(r.status), int((time.time() - t0) * 1000), None
    except urllib.error.HTTPError as exc:
        return int(exc.code), int((time.time() - t0) * 1000), None
    except Exception as exc:  # noqa: BLE001 — connection refused, DNS, TLS, timeout
        return None, int((time.time() - t0) * 1000), f"{type(exc).__name__}: {exc}"


def status_ok(status, expect):
    """v3.8 §8: a SUCCESS is required unless the journey declares an explicit contract."""
    if status is None:
        return False
    if expect is not None:
        exps = expect if isinstance(expect, list) else [expect]
        return status in [e for e in exps if isinstance(e, int)]
    return 200 <= status < 300


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:  # noqa: BLE001
        return None


def declared_journeys(workdir, ctx):
    """(journeys, source). `<workdir>/cujs.json` first, then ledger entries flagged cuj:true."""
    explicit = ctx.option("cujs")
    if isinstance(explicit, list) and explicit:
        return [j for j in explicit if isinstance(j, dict)], "option:cujs"

    doc = _load_json(Path(workdir) / "cujs.json")
    items = None
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        for key in ("journeys", "cujs", "entries"):
            if isinstance(doc.get(key), list):
                items = doc[key]
                break
    if items:
        return [j for j in items if isinstance(j, dict)], "cujs.json"

    ledger = ctx.option("ledger_payload")
    if not isinstance(ledger, dict):
        ledger = _load_json(Path(workdir) / "ledger.json")
    out = []
    if isinstance(ledger, dict):
        buckets = []
        if isinstance(ledger.get("entries"), list):
            buckets.append(ledger["entries"])
        for sec in ("backend_routes", "frontend_calls", "spec_features"):
            if isinstance(ledger.get(sec), list):
                buckets.append(ledger[sec])
        for bucket in buckets:
            for it in bucket:
                if isinstance(it, dict) and it.get("cuj") is True:
                    out.append(it)
    return out, "ledger.json (entries flagged cuj:true)"


def _probe_index(workdir, ctx):
    """(method, path) -> route record from the RUNTIME_PROBE observation."""
    probe = ctx.option("probe_payload")
    if not isinstance(probe, dict):
        probe = _load_json(Path(workdir) / "probe.json")
    index = {}
    if isinstance(probe, dict):
        for r in probe.get("routes") or []:
            if isinstance(r, dict):
                index[(str(r.get("method", "")).upper(), str(r.get("path", "")))] = r
    return index


class CujCollector(Collector):
    """Evidence every declared Critical User Journey end to end.

    Options: `cujs`, `base_url`, `cuj_timeout` (default 600), `mock_target`,
    `probe_payload` / `ledger_payload`.
    """

    kind = EvidenceKind.CUJ
    name = "cuj"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        base = (ctx.option("base_url") or "").strip()
        timeout = int(ctx.option("cuj_timeout", 600) or 600)
        mock_target = bool(ctx.option("mock_target"))

        journeys, source = declared_journeys(workdir, ctx)
        index = _probe_index(workdir, ctx)

        out = []
        for i, j in enumerate(journeys):
            out.append(self._one(ctx, root, base, timeout, mock_target, index, i, j))

        payload = {
            "journeys": out,
            "declaredCount": len(out),
            "source": source,
        }
        evidenced = sum(1 for j in out if j["status"] == "EVIDENCED")
        uncovered = []
        if not out:
            uncovered.append("cuj: no Critical User Journey was declared, so none was evidenced")
        note = f"{evidenced}/{len(out)} Critical User Journey(s) evidenced (source: {source})"
        return self.collected(ctx, payload, note=note, uncovered=uncovered)

    def _one(self, ctx, root, base, timeout, mock_target, index, i, j):
        jid = str(j.get("id") or j.get("name") or j.get("label") or j.get("path") or f"cuj-{i + 1}")
        title = str(j.get("title") or j.get("name") or j.get("label") or jid)
        mocked = bool(j.get("mocked") or j.get("mock") or mock_target)
        method = str(j.get("method") or "GET").upper()
        path = j.get("path")
        cmd = (j.get("cmd") or j.get("command") or "").strip()

        if cmd:
            res = self._exec(ctx, root, cmd, timeout)
            if not hasattr(res, "returncode"):
                return self._row(jid, title, "ERROR", mocked, None,
                                 f"the journey command could not be run ({res})")
            if res.timed_out or res.returncode in ERROR_RCS:
                # FIX-CUJ-ERROR-IS-NOT-A-VERDICT
                return self._row(jid, title, "ERROR", mocked, f"cmd:rc={res.returncode}",
                                 f"the journey command did not complete (rc={res.returncode}, "
                                 f"timedOut={res.timed_out}); the journey's outcome is unknown")
            if res.returncode == 0:
                return self._row(jid, title, "EVIDENCED", mocked, "cmd:rc=0",
                                 f"the scripted journey completed: {cmd}")
            tail = ((res.stdout or "") + (res.stderr or ""))[-200:].strip()
            return self._row(jid, title, "NOT_EVIDENCED", mocked, f"cmd:rc={res.returncode}",
                             f"the scripted journey failed (rc={res.returncode}): {tail}")

        if path and base:
            status, ms, err = http_probe(base, method, str(path))
            if err is not None:
                return self._row(jid, title, "NOT_EVIDENCED", mocked, None,
                                 f"{method} {path} did not answer: {err}")
            ok = status_ok(status, j.get("expect_status"))
            ref = f"http:{method} {path} -> {status}"
            if ok:
                return self._row(jid, title, "EVIDENCED", mocked, ref,
                                 f"{method} {path} answered {status} in {ms}ms")
            return self._row(jid, title, "NOT_EVIDENCED", mocked, ref,
                             f"{method} {path} answered {status}; the server answering is not the "
                             f"journey completing")

        if path:
            hit = index.get((method, str(path))) or index.get(("GET", str(path)))
            if hit is not None:
                judgment = str(hit.get("judgment", "")).upper()
                ref = f"probe:{method} {path} -> {hit.get('status')}"
                if judgment == "SERVED":
                    return self._row(jid, title, "EVIDENCED", mocked, ref,
                                     f"served against the 404 canary baseline: {hit.get('detail', '')}")
                if judgment == "MOCKED":
                    # FIX-CUJ-MOCK-IS-DECLARED: evidenced, but against a mock — upstream refuses it.
                    return self._row(jid, title, "EVIDENCED", True, ref,
                                     "evidenced against a MOCK; a test that mocks X is no evidence "
                                     "about X")
                if judgment == "ABSENT":
                    return self._row(jid, title, "NOT_EVIDENCED", mocked, ref,
                                     f"the route is not served: {hit.get('detail', '')}")
                return self._row(jid, title, "ERROR", mocked, ref,
                                 f"the runtime probe was inconclusive ({judgment or 'unknown'}), so "
                                 f"the journey's outcome is unknown")
            return self._row(jid, title, "NOT_EVIDENCED", mocked, None,
                             f"no runtime observation for {method} {path} and no base URL to probe "
                             f"it against")

        return self._row(jid, title, "NOT_EVIDENCED", mocked, None,
                         "the journey declares neither a command nor a path, so nothing could be "
                         "exercised")

    def _row(self, jid, title, status, mocked, ref, detail):
        return {"id": jid, "title": title, "status": status, "mocked": bool(mocked),
                "evidenceRef": ref, "detail": detail}

    def _exec(self, ctx, root, command, timeout):
        try:
            return ctx.adapter.run_target(command=command, cwd=str(root), timeout=timeout,
                                          network=True, label=f"cuj: {command}")
        except Exception as exc:  # noqa: BLE001
            return exc
