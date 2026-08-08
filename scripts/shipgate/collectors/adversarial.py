"""ADVERSARIAL_PROBE collector — the falsifiable core of Phase H, mechanised.

WHY THIS EXISTS. Phase H, the adversarial round, was written procedure only: an instruction
to the operating agent, observed by nothing. In a behaviour evaluation an agent reached
VERIFIED without running it, then ran it on request and found two MAJOR defects in about two
minutes — `parseInt('1abc') === 1` in an ID parser, so a crafted request returned another
user's resource, and a malformed request body causing an unhandled 500. Neither of those is
judgement. Both are textbook bug classes with a mechanical oracle, and leaving them to
operator discipline is what let a live authorisation bypass ship under a green headline.

So the falsifiable part of Phase H is a collector, and only the genuinely creative residue
stays self-attested (see `models.coverage`). Two families:

  ID COERCION / BOLA DIFFERENTIAL. Two identities, each owning a resource with a
  distinguishing marker. Every request made AS one identity is checked against the OTHER
  identity's marker, across a family of coercible spellings of the victim's id — `1abc`,
  `01`, ` 1`, `1.0`, `1e0`, `+1`, `1%00`, `1/`, `1#`. The asserted property is a single
  sentence: *a request authenticated as A must never return B's marker.* That is what
  `parseInt('1abc')` violates, and it holds regardless of which coercion bug produced the
  violation — the probe does not need to model the mechanism, only the consequence.

  MALFORMED INPUT. Every write endpoint, given input no client should ever send: truncated
  JSON, wrong types, a missing required field, an oversized string, a deeply nested object,
  a null byte, an empty body, the wrong content type. The asserted property: *the response
  must be a 4xx, never a 5xx, and must not contain a stack trace.* An honest refusal is a
  pass; a crash is a finding.

FAIL-FIRST ADMISSION, AND WHY IT IS NOT OPTIONAL. This kit already refuses to count a test
that has never failed on an injected fault. Promoting an adversarial probe to COLLECTED
evidence without the same rule would be strictly worse than leaving Phase H self-attested:
a shallow probe would stamp "adversarially tested" on an app nobody meaningfully attacked,
laundering false confidence into the most-trusted evidence class in the system. So before
any result against the real target is admitted, both families run against two in-memory
reference applications:

    a VULNERABLE one, which must be FLAGGED — a probe that cannot catch the bug it is
    named after has not demonstrated it can catch anything;
    a CORRECT one, which must be CLEAN — a probe that flags everything is not a probe,
    it is a stuck alarm, and it would make every target look attacked.

Both directions, every run, before admission. If either fails, the evidence is ERROR and the
gate fails closed: an inadmissible probe is not a passing probe.

The reference applications are IN-MEMORY, reached through an injected transport rather than
a socket. That is deliberate. A self-test that binds a port fails in restricted sandboxes and
CI images, and a flaky admission check is one somebody eventually disables. This one has no
network, no process and no clock in it, so it produces the same answer everywhere.

HTTP against the real target is `urllib`, in-process, exactly as `probe.py` does it. No
process is spawned, so the execution adapter is not involved — the adapter exists for
spawning, and a collector must never spawn.
"""
import json
import re
from pathlib import Path
from urllib.parse import quote, unquote
from typing import Any, Dict, List, Optional, Tuple

from ..models.evidence import EvidenceKind
from .base import Collector
from .probe import LOCAL_HOSTS, WRITE_METHODS, request as http_request

#: Spellings of an id that a weak parser may coerce back to the original. The list is the
#: probe's whole hypothesis space for the coercion family, so it is data, not scattered
#: string literals — `describe()` prints it and the reference applications are built to
#: exercise it.
#: Templates hold LITERAL characters; `coercion_probe` percent-encodes the result. Writing
#: `%00` and `%23` directly here was a defect: two spellings (` {id}` and `{id} `) contained
#: a raw space, which `urllib` refuses to put in a URL, so those probes died in the client
#: with a transport error and were recorded INCONCLUSIVE — which fails closed, so a perfectly
#: correct application could not pass this check. The probe was generating requests it could
#: not send. Encoding at send time makes every spelling transmissible, and it is also what a
#: real attacker's client does.
COERCIONS = (
    ("exact", "{id}"),
    ("trailing_alpha", "{id}abc"),         # parseInt('1abc') === 1
    ("leading_zero", "0{id}"),
    ("leading_space", " {id}"),
    ("trailing_space", "{id} "),
    ("float_form", "{id}.0"),
    ("exponent_form", "{id}e0"),
    ("plus_sign", "+{id}"),
    ("null_byte", "{id}\x00"),
    ("trailing_slash", "{id}/"),
    ("fragment", "{id}#x"),
    ("array_suffix", "{id}[]"),
)

#: Malformed bodies: (name, raw body, structurally_invalid).
#:
#: `structurally_invalid` is what separates a defect from a design choice, and getting it
#: wrong in either direction breaks the probe. A body that cannot be a JSON OBJECT at all —
#: truncated, empty, not JSON, an array, a bare `null` — has no valid interpretation, so a
#: 2xx means the handler wrote something it never parsed, which is a finding. The rest are
#: legal JSON carrying hostile CONTENT: an API with no required fields may accept
#: `{"a":1,"a":2}` and be perfectly correct, so for those only a 5xx or a leaked trace
#: counts. Flagging a lawful 201 would make the probe the stuck alarm that the admission
#: check exists to catch, and it would do it on real targets rather than on the reference
#: app, where nobody would see it.
MALFORMATIONS = (
    ("truncated_json", '{"a":', True),
    ("empty_body", "", True),
    ("not_json", "<<<not json at all>>>", True),
    ("null_literal", "null", True),
    ("array_where_object", "[1,2,3]", True),
    ("wrong_types", '{"__shipgate_probe":{"nested":true},"n":"not-a-number"}', False),
    ("oversized_string", '{"__shipgate_probe":"' + ("A" * 20000) + '"}', False),
    ("deep_nesting", '{"a":' * 60 + "1" + "}" * 60, False),
    ("null_byte_in_string", '{"__shipgate_probe":"a\\u0000b"}', False),
    ("duplicate_keys", '{"a":1,"a":2}', False),
)

#: Substrings that mean the server handed an internal error to the client. Matched
#: case-insensitively against the first few KB of the body. Deliberately narrow: a page
#: that merely contains the word "error" is not a stack trace, and treating it as one
#: would make the probe the stuck alarm the admission check exists to catch.
TRACE_MARKERS = (
    "traceback (most recent call last)",
    "at java.", "javax.servlet", "org.springframework.",
    "\n    at ", " at Object.", " at Module.",
    "goroutine ", "panic: ",
    "system.nullreferenceexception", "microsoft.aspnetcore",
    "stack trace:", "stacktrace",
    "sqlalchemy.exc.", "psycopg2.", "django.db.utils",
    "error: connect econnrefused",
)

#: The header a probe request always carries, so an operator reading their own access log
#: can tell which requests were the gate's. Not a security control — a target that changes
#: behaviour when it sees this header is a target that is lying to the gate, and there is
#: no header value that fixes that.
PROBE_HEADER_VALUE = "shipgate-adversarial-probe"

#: The last path segment, when it looks like an IDENTIFIER rather than a collection name.
#:
#: "Looks like" means it contains a digit. `/api/orders/42` and
#: `/api/orders/3f2a-9c1b` are ids; `/api/orders` is a collection, and rewriting `orders`
#: into `ordersabc` would send twelve requests to a nonsense path and call the result a
#: clean differential. Requiring a digit is a heuristic, so the failure mode matters: a
#: purely alphabetic id (a slug, say) is reported as UNCOVERED rather than silently
#: skipped, which fails toward saying so.
_ID_IN_PATH = re.compile(r"^(?P<head>.*/)(?P<id>[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)(?P<tail>/?)$")


class AdversarialError(ValueError):
    """The probe cannot be configured. Always becomes ERROR evidence, never a silent skip."""


# =======================================================================================
# transport
# =======================================================================================


def live_transport(timeout):
    """The real one: urllib against the target, no redirects (inherited from `probe`)."""
    def send(method, url, token=None, body=None, raw=None, content_type=None):
        if raw is not None:
            return _raw_request(method, url, token, raw, content_type, timeout)
        return http_request(method, url, token=token, body=body, timeout=timeout)
    return send


def _raw_request(method, url, token, raw, content_type, timeout):
    """Send an arbitrary byte body. `http_request` JSON-encodes, which cannot express
    'truncated JSON' or 'not JSON at all' — the two malformations that matter most."""
    import urllib.error
    import urllib.request
    from .probe import _OPENER
    headers = {"Accept": "application/json",
               "Content-Type": content_type or "application/json",
               "X-Shipgate-Probe": PROBE_HEADER_VALUE}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=raw.encode("utf-8", "surrogatepass"),
                                 headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return int(r.status), r.read(8000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read(8000).decode("utf-8", "replace")
        except Exception:
            text = ""
        return int(exc.code), text
    except Exception as exc:
        return 0, f"TRANSPORT-ERROR {type(exc).__name__}: {exc}"


# =======================================================================================
# the two probe families — pure functions of (transport, config)
# =======================================================================================


def _split_id(path):
    m = _ID_IN_PATH.match(path or "")
    if not m:
        return None
    return m.group("head"), m.group("id"), m.group("tail")


def coercion_probe(send, base, identities) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The BOLA differential. Returns (results, uncovered).

    `identities` is [{label, token, resource, marker}]. `resource` is a path ending in the
    id of something that identity owns; `marker` is a string that appears in that
    resource's representation and in NO other identity's.
    """
    results, uncovered = [], []
    for victim in identities:
        split = _split_id(victim.get("resource"))
        if not split:
            uncovered.append(
                f"identity {victim.get('label')!r}: resource "
                f"{victim.get('resource')!r} does not end in an id-shaped segment (one "
                "containing a digit), so no coercion of it can be constructed. Point "
                "`resource` at a specific record, not at a collection.")
            continue
        head, vid, tail = split
        marker = str(victim.get("marker") or "")
        if not marker:
            uncovered.append(f"identity {victim.get('label')!r}: no marker declared, so a "
                             "leak of this resource could not be recognised")
            continue
        for attacker in identities:
            if attacker.get("label") == victim.get("label"):
                continue
            for coercion, template in COERCIONS:
                # `safe="/"` keeps the path separator a separator — `trailing_slash` is
                # testing routing, not an encoded character — while everything else that
                # cannot travel raw becomes a percent-escape.
                path = head + quote(template.format(id=vid), safe="/") + tail
                status, body = send("GET", base + path, token=attacker.get("token"))
                leaked = marker in (body or "")
                results.append({
                    "family": "id_coercion",
                    "id": f"{attacker.get('label')}->{victim.get('label')}:{coercion}",
                    "attacker": attacker.get("label"),
                    "victim": victim.get("label"),
                    "coercion": coercion,
                    "path": path,
                    "status": int(status),
                    "leaked": leaked,
                    "verdict": "FINDING" if leaked else (
                        "INCONCLUSIVE" if status == 0 else "CLEAN"),
                    "detail": (
                        f"authenticated as {attacker.get('label')}, the response to "
                        f"{path} contained {victim.get('label')}'s marker — the "
                        f"authorisation check did not hold under the {coercion!r} spelling "
                        f"of the id"
                        if leaked else
                        ("no response (transport error), so nothing was established"
                         if status == 0 else
                         f"status {status}, no cross-identity marker in the body")),
                })
    return results, uncovered


def malformed_probe(send, base, endpoints) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The malformed-input property. Returns (results, uncovered).

    `endpoints` is [{method, path}] for write endpoints the caller authorised.
    """
    results, uncovered = [], []
    for ep in endpoints:
        method = str(ep.get("method") or "POST").upper()
        path = ep.get("path") or "/"
        if method not in WRITE_METHODS:
            uncovered.append(f"{method} {path}: not a write method")
            continue
        for name, payload, structurally_invalid in MALFORMATIONS:
            ctype = "text/plain" if name == "not_json" else "application/json"
            status, body = send(method, base + path, token=ep.get("token"),
                                raw=payload, content_type=ctype)
            trace = _trace_marker(body)
            if status == 0:
                verdict, detail = "INCONCLUSIVE", "no response (transport error)"
            elif 500 <= status < 600:
                verdict, detail = "FINDING", (
                    f"status {status}: a malformed body should be refused with a 4xx, not "
                    f"crash the handler")
            elif trace:
                verdict, detail = "FINDING", (
                    f"status {status} but the body leaks an internal trace ({trace!r})")
            elif 200 <= status < 300 and structurally_invalid:
                verdict, detail = "FINDING", (
                    f"status {status}: the {name!r} body was ACCEPTED, and it cannot be "
                    f"parsed as a JSON object at all — the handler wrote something it "
                    f"never read")
            else:
                verdict, detail = "CLEAN", f"status {status}: refused without crashing"
            results.append({
                "family": "malformed_input",
                "id": f"{method} {path}:{name}",
                "method": method, "path": path, "malformation": name,
                "structurallyInvalid": structurally_invalid,
                "status": int(status), "verdict": verdict, "detail": detail,
            })
    return results, uncovered


def _trace_marker(body):
    low = (body or "")[:8000].lower()
    for marker in TRACE_MARKERS:
        if marker in low:
            return marker
    return ""


# =======================================================================================
# fail-first admission: two in-memory reference applications
# =======================================================================================


_REF_IDENTITIES = (
    {"label": "A", "token": "token-a", "resource": "/api/orders/1", "marker": "ORDER-A-SECRET"},
    {"label": "B", "token": "token-b", "resource": "/api/orders/2", "marker": "ORDER-B-SECRET"},
)
_REF_ENDPOINTS = ({"method": "POST", "path": "/api/orders", "token": "token-a"},)
_REF_OWNER = {"1": ("token-a", "ORDER-A-SECRET"), "2": ("token-b", "ORDER-B-SECRET")}


def _ref_id_from(url):
    """Decode the id the way a real server does before routing.

    The live bench application calls `decodeURIComponent`; every web framework does the
    equivalent. A reference app that skipped it would see `%202` where a real target sees
    ` 2`, and the seeded bug would stop being reachable — the admission check would then be
    proving something about an unrealistic app.
    """
    tail = url.split("/api/orders/", 1)[1] if "/api/orders/" in url else ""
    return unquote(tail).rstrip("/")


def _serve(handler, method, url, token, body, raw, content_type):
    """The framework boundary the reference handlers run behind.

    A web framework does not let a handler exception escape to the socket — it turns it
    into a 500 with whatever diagnostic the app was configured to leak. Modelling that here
    is what makes the seeded unhandled-error bug reachable by the probe as a RESPONSE rather
    than as a Python exception escaping through the transport, which is not a thing a real
    target can do to us.
    """
    try:
        return handler(method, url, token, body, raw, content_type)
    except Exception as exc:                       # noqa: BLE001 — modelling a 500 on purpose
        return 500, (f'{{"error":"internal server error"}}\nTraceback (most recent call '
                     f'last):\n  File "app.py", line 42\n{type(exc).__name__}: {exc}')


def vulnerable_app(method, url, token=None, body=None, raw=None, content_type=None):
    """The reference application WITH the two bugs. The probe must flag it."""
    return _serve(_vulnerable_handler, method, url, token, body, raw, content_type)


def _vulnerable_handler(method, url, token, body, raw, content_type):
    """Bug 1 reproduces the incident exactly: the ownership check is done on the RAW
    spelling (so `'1abc' != '1'` and the guard is skipped for a non-owner) while the LOOKUP
    uses an int coercion that maps `'1abc'` back to `1`. Bug 2 is an unguarded parse: any
    body that is not the JSON object the handler assumed raises, and the framework turns
    that into a 500."""
    if "/api/orders/" in url:
        raw_id = _ref_id_from(url)
        try:
            coerced = str(_parse_int_prefix(raw_id))
        except ValueError:
            return 404, '{"error":"not found"}'
        owner = _REF_OWNER.get(coerced)
        if owner is None:
            return 404, '{"error":"not found"}'
        owner_token, marker = owner
        # THE BUG: the guard compares the RAW spelling, the lookup used the coerced one.
        if raw_id == coerced and token != owner_token:
            return 403, '{"error":"forbidden"}'
        return 200, json.dumps({"id": coerced, "secret": marker})
    if method in WRITE_METHODS:
        doc = json.loads(raw if raw is not None else json.dumps(body))   # THE BUG: unguarded
        if not isinstance(doc, dict):
            doc = {"_": doc}
        return 201, json.dumps({"created": True, "keys": sorted(doc.keys())})
    return 404, '{"error":"not found"}'


def correct_app(method, url, token=None, body=None, raw=None, content_type=None):
    """The reference application WITHOUT the bugs. The probe must leave it clean."""
    return _serve(_correct_handler, method, url, token, body, raw, content_type)


def _correct_handler(method, url, token, body, raw, content_type):
    if "/api/orders/" in url:
        raw_id = _ref_id_from(url)
        if not raw_id.isdigit():
            return 400, '{"error":"malformed id"}'
        owner = _REF_OWNER.get(raw_id)
        if owner is None:
            return 404, '{"error":"not found"}'
        owner_token, marker = owner
        if token != owner_token:
            return 403, '{"error":"forbidden"}'
        return 200, json.dumps({"id": raw_id, "secret": marker})
    if method in WRITE_METHODS:
        if content_type != "application/json":
            return 415, '{"error":"unsupported media type"}'
        try:
            doc = json.loads(raw if raw is not None else json.dumps(body))
        except (ValueError, TypeError):
            return 400, '{"error":"malformed body"}'
        if not isinstance(doc, dict):
            return 400, '{"error":"expected an object"}'
        if any(isinstance(v, str) and len(v) > 4096 for v in doc.values()):
            return 413, '{"error":"payload too large"}'
        if not doc.get("item"):
            return 422, '{"error":"item is required"}'
        return 201, '{"created":true}'
    return 404, '{"error":"not found"}'


def _parse_int_prefix(text):
    """`parseInt` semantics: leading integer prefix, ignoring whitespace and a sign."""
    m = re.match(r"^\s*([+-]?\d+)", text or "")
    if not m:
        raise ValueError(text)
    return int(m.group(1))


def _admission_run(app):
    findings = []
    coercion, _ = coercion_probe(app, "", list(_REF_IDENTITIES))
    malformed, _ = malformed_probe(app, "", list(_REF_ENDPOINTS))
    for r in coercion + malformed:
        if r["verdict"] == "FINDING":
            findings.append(r["id"])
    return findings


def admission() -> Dict[str, Any]:
    """Run both families against both reference applications. The fail-first gate.

    Returns a record, never raises. `admitted` is True only when the vulnerable app was
    flagged AND the correct app came back clean — a probe that catches nothing and a probe
    that flags everything are equally useless, and only checking one direction would let
    one of them through.
    """
    caught = _admission_run(vulnerable_app)
    false_alarms = _admission_run(correct_app)
    coercion_caught = any(r.startswith("A->B") or r.startswith("B->A") for r in caught)
    malformed_caught = any(r.startswith("POST ") for r in caught)
    admitted = bool(coercion_caught and malformed_caught and not false_alarms)
    # `defectClasses` / `caught` mirror the other three phase checkers so `gate.py doctor`
    # can print all four uniformly. Phase H's classes are families rather than named kinds:
    # the probe enumerates dozens of concrete coercions and malformations, but it is only
    # admitted when at least one of EACH family lands on the vulnerable reference.
    families = ("id_coercion", "malformed_input")
    caught_families = [name for name, hit in
                       (("id_coercion", coercion_caught), ("malformed_input", malformed_caught))
                       if hit]
    return {
        "admitted": admitted,
        "defectClasses": list(families),
        "caught": caught_families,
        "missed": [f for f in families if f not in caught_families],
        "seededFindings": sorted(caught),
        "seededFindingCount": len(caught),
        "coercionFamilyCaught": coercion_caught,
        "malformedFamilyCaught": malformed_caught,
        "falseAlarmsOnCorrectApp": sorted(false_alarms),
        "detail": (
            "both families caught their seeded defect on the vulnerable reference app and "
            "neither fired on the correct one"
            if admitted else
            "; ".join(filter(None, [
                "" if coercion_caught else
                "the id-coercion family did NOT catch its seeded BOLA",
                "" if malformed_caught else
                "the malformed-input family did NOT catch its seeded unhandled error",
                f"{len(false_alarms)} false alarm(s) on the correct reference app: "
                f"{sorted(false_alarms)[:4]}" if false_alarms else "",
            ]))),
    }


# =======================================================================================
# the collector
# =======================================================================================


class AdversarialProbeCollector(Collector):
    """Mechanised Phase H: the ID-coercion differential and the malformed-input property.

    Options:
      `base_url`                  required, same value Phase D used
      `adversarial_identities`    [{label, token, resource, marker}] — at least two
      `adversarial_endpoints`     [{method, path, token}] write endpoints to malform
      `adversarial_config`        path to a JSON file holding either/both of the above
      `allow_writes`              required before any write endpoint is malformed
      `allow_nonlocal_writes`     required as well when the target is not local
      `probe_timeout`             seconds, default 20
    """

    kind = EvidenceKind.ADVERSARIAL_PROBE
    name = "adversarial-probe"
    version = "4.2.4"

    def collect(self, ctx):
        # ADMISSION FIRST. Before anything is measured against the real target, prove the
        # instrument works. An unadmitted probe cannot produce a passing observation, so
        # there is no ordering in which a broken probe's results reach the engine.
        adm = admission()
        if not adm["admitted"]:
            return self.error(
                ctx,
                "the adversarial probe FAILED its own fail-first admission and was not run "
                f"against the target: {adm['detail']}",
                payload={"admission": adm})

        base = (ctx.option("base_url") or "").strip().rstrip("/")
        if not base:
            return self.error(ctx, "no base_url option was supplied, so nothing could be "
                                   "attacked; an adversarial round that sent no request is "
                                   "not an adversarial round")

        identities, endpoints, config_note = self._config(ctx)
        if not identities and not endpoints:
            # ABSENT, not ERROR and not an empty pass. The gate cannot invent two disposable
            # accounts for somebody's application, so "nothing was declared" is a statement
            # about the configuration, not about the target. It is also not swept away: the
            # Phase H coverage caveat is cleared ONLY by collected adversarial evidence, so
            # this run is reported as `VERIFIED — partial coverage (H not run)`, and on the
            # `deep` profile this evidence is required and its absence fails the run.
            return self.absent(
                ctx,
                "no adversarial identities and no write endpoints were declared, so the "
                "probe had nothing to attack. Declare two disposable accounts and the "
                "resource each owns in `adversarial-config.json` (see "
                "assets/templates/adversarial-config.json) — Phase H coverage stays "
                "UNCOLLECTED until you do.")
        timeout = int(ctx.option("probe_timeout", 20) or 20)
        send = live_transport(timeout)

        uncovered: List[str] = []
        results: List[Dict[str, Any]] = []

        # --- family 1: id coercion ---------------------------------------------------------
        if len(identities) < 2:
            uncovered.append(
                "id-coercion differential: fewer than two identities were declared, so "
                "'A must never see B's data' has no B. Declare two disposable accounts with "
                "`adversarial_identities` (see assets/templates/adversarial-config.json).")
        else:
            found, unc = coercion_probe(send, base, identities)
            results += found
            uncovered += unc

        # --- family 2: malformed input -----------------------------------------------------
        host = _host_of(base)
        writes_ok = bool(ctx.option("allow_writes")) and (
            host in LOCAL_HOSTS or bool(ctx.option("allow_nonlocal_writes")))
        if not endpoints:
            uncovered.append("malformed-input property: no write endpoint was declared")
        elif not writes_ok:
            uncovered.append(
                f"malformed-input property: writes were not authorised for host {host!r}; "
                "malforming a body means SENDING it, so this family is never run without "
                "allow_writes (and allow_nonlocal_writes off localhost)")
        else:
            found, unc = malformed_probe(send, base, endpoints)
            results += found
            uncovered += unc

        counts = {"CLEAN": 0, "FINDING": 0, "INCONCLUSIVE": 0}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        counts["total"] = len(results)

        findings = [r for r in results if r["verdict"] == "FINDING"]
        payload = {
            "baseUrl": base,
            "admission": adm,
            "identities": [{"label": i.get("label"), "resource": i.get("resource")}
                           for i in identities],          # tokens and markers never recorded
            "endpoints": [{"method": e.get("method"), "path": e.get("path")}
                          for e in endpoints],
            "coercions": [name for name, _ in COERCIONS],
            "malformations": [name for name, _, _ in MALFORMATIONS],
            "results": results,
            "counts": counts,
            "findings": [{"id": f["id"], "family": f["family"], "detail": f["detail"]}
                         for f in findings],
            "configNote": config_note,
        }
        self._persist(ctx, payload)
        note = (f"{counts['total']} adversarial probe(s): {counts['FINDING']} finding(s), "
                f"{counts['INCONCLUSIVE']} inconclusive; admission passed with "
                f"{adm['seededFindingCount']} seeded defect(s) caught")
        return self.collected(ctx, payload, note=note, uncovered=tuple(uncovered))

    # -- configuration ------------------------------------------------------------------
    def _config(self, ctx):
        identities = _as_list(ctx.option("adversarial_identities"))
        endpoints = _as_list(ctx.option("adversarial_endpoints"))
        note = "identities/endpoints supplied as options"
        path = ctx.option("adversarial_config")
        if not path:
            default = Path(ctx.workdir or ".") / "adversarial-config.json"
            path = str(default) if default.is_file() else ""
        if path:
            try:
                doc = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise AdversarialError(
                    f"adversarial config {path!r} is unreadable ({type(exc).__name__}: "
                    f"{exc}); a probe that silently ran with no configuration would report "
                    "a clean adversarial round having attacked nothing") from None
            if not isinstance(doc, dict):
                raise AdversarialError(f"adversarial config {path!r} is not an object")
            identities = identities or _as_list(doc.get("identities"))
            endpoints = endpoints or _as_list(doc.get("endpoints"))
            note = f"configuration read from {path}"
        return (_clean_identities(identities), _clean_endpoints(endpoints), note)

    def _persist(self, ctx, payload):
        workdir = Path(ctx.workdir) if ctx.workdir else None
        if workdir is None:
            return
        try:
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "adversarial.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass          # the evidence is the payload; the file is a convenience


def _host_of(base):
    import urllib.parse
    return (urllib.parse.urlparse(base).hostname or "").lower()


def _as_list(v):
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _clean_identities(raw):
    out, seen = [], set()
    for i, item in enumerate(raw):
        label = str(item.get("label") or f"id{i}")
        if label in seen:
            continue
        seen.add(label)
        out.append({"label": label,
                    "token": item.get("token"),
                    "resource": str(item.get("resource") or ""),
                    "marker": str(item.get("marker") or "")})
    return out


def _clean_endpoints(raw):
    out = []
    for item in raw:
        out.append({"method": str(item.get("method") or "POST").upper(),
                    "path": str(item.get("path") or "/"),
                    "token": item.get("token")})
    return out


def describe() -> str:
    """What the probe covers, for `gate.py doctor`. Includes what it does NOT cover."""
    lines = [
        "ADVERSARIAL_PROBE — the mechanised core of Phase H.",
        "",
        f"  id-coercion spellings ({len(COERCIONS)}): "
        + ", ".join(n for n, _ in COERCIONS),
        f"  malformations ({len(MALFORMATIONS)}): "
        + ", ".join(n for n, _, _ in MALFORMATIONS),
        "",
        "  Admitted only after catching a seeded BOLA and a seeded unhandled error on an",
        "  in-memory vulnerable reference app, AND staying silent on a correct one.",
        "",
        "  NOT covered, and still Phase H's job by hand: sequence hostility (double-submit,",
        "  back-button, expired session mid-form), state hostility (concurrent edits, empty",
        "  and at-limit accounts), environment hostility (dependency killed mid-request),",
        "  and spec-boundary mining. Those stay self-attested — see models/coverage.py.",
    ]
    return "\n".join(lines)
