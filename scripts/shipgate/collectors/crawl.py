"""UI_CRAWL / ACCESSIBILITY / PERFORMANCE collectors.

Ported from v3.8 `crawl.py`. The browser work itself is unchanged in substance — the same
three viewports, the same interactive-element sweep with a MutationObserver counting REAL
mutations, the same form fill-and-submit pass, the same high-precision destructive-label
denylist, the same local-axe-then-CDN lookup, the same "a layer that could not run is
UNVERIFIED, never a violation" rule.

What changed is HOW it runs. Playwright is a third-party package, so it may not be imported
by the gate: the browser work is emitted as a driver script and executed through
`ctx.adapter.run_target(...)`, the single execution chokepoint. A missing Playwright, a
missing browser binary or a base URL that will not load produces ERROR evidence — never an
empty-but-clean-looking payload.

All three collectors share one browser run: the first to execute caches the driver's output
in `<workdir>/crawl.json`, and the others reuse it.
"""
import json
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

DRIVER_REL = "shipgate-workdir/_sg_ui_driver.py"
EVIDENCE_REL = "shipgate-ui-evidence"
MARKER = "<<<SHIPGATE-CRAWL-JSON>>>"
IMPACTS = ("critical", "serious", "moderate", "minor")

# The driver runs OUTSIDE this process, under the adapter's boundary. It is gate-authored
# text; nothing target-controlled is interpolated into it.
DRIVER_SOURCE = r'''#!/usr/bin/env python3
"""ship-gate UI evidence driver. Runs under the execution adapter; prints one JSON blob."""
import json, re, sys, time
from pathlib import Path

MARKER = "<<<SHIPGATE-CRAWL-JSON>>>"

#: Computed-style census. Counts VISIBLE elements only — a hidden node's computed colour is
#: not something a user can see, and counting it would make the conformance diff argue about
#: markup nobody renders. Capped at 4000 elements and the top 60 of each dimension so the
#: payload stays bounded whatever the page.
STYLE_CENSUS_JS = """() => {
  const tally = {color: {}, background: {}, fontFamily: {}, fontSize: {}, spacing: {},
                 borderRadius: {}};
  const bump = (b, k) => { if (k) b[k] = (b[k] || 0) + 1; };
  const els = Array.from(document.querySelectorAll('body *')).slice(0, 4000);
  let counted = 0;
  for (const el of els) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') continue;
    counted++;
    bump(tally.color, cs.color);
    if (cs.backgroundColor && cs.backgroundColor !== 'rgba(0, 0, 0, 0)')
      bump(tally.background, cs.backgroundColor);
    bump(tally.fontFamily, (cs.fontFamily || '').split(',')[0].replace(/["']/g, '').trim());
    bump(tally.fontSize, cs.fontSize);
    bump(tally.borderRadius, cs.borderRadius);
    for (const prop of ['marginTop','marginBottom','marginLeft','marginRight',
                        'paddingTop','paddingBottom','paddingLeft','paddingRight','gap']) {
      const v = cs[prop];
      if (v && v !== '0px' && v !== 'normal') bump(tally.spacing, v);
    }
  }
  const top = (b) => Object.entries(b).sort((a, z) => z[1] - a[1] || (a[0] < z[0] ? -1 : 1))
                       .slice(0, 60).map(([value, count]) => ({value, count}));
  const out = {elementsCounted: counted};
  for (const k of Object.keys(tally)) out[k] = top(tally[k]);
  return out;
}"""

#: Text census. Action labels, navigation labels, headings, and the raw text of anything that
#: looks like a date, a currency amount or a formatted number — which is what a cross-surface
#: consistency check compares. Trimmed, deduplicated and sorted.
TEXT_CENSUS_JS = """() => {
  const clean = (t) => (t || '').replace(/\\s+/g, ' ').trim().slice(0, 80);
  const uniq = (a) => Array.from(new Set(a.filter(Boolean))).sort().slice(0, 120);
  const actions = uniq(Array.from(document.querySelectorAll(
      'button, [role=button], input[type=submit], input[type=button], a[href]'))
    .map(e => clean(e.getAttribute('aria-label') || e.value || e.innerText)));
  const nav = uniq(Array.from(document.querySelectorAll('nav a, [role=navigation] a, header a'))
    .map(e => clean(e.innerText)));
  const headings = uniq(Array.from(document.querySelectorAll('h1,h2,h3'))
    .map(e => clean(e.innerText)));
  const body = clean(document.body ? document.body.innerText : '').slice(0, 20000);
  const grab = (re) => uniq((body.match(re) || []).map(clean));
  return {
    actions: actions, nav: nav, headings: headings,
    dates: grab(/\\b(\\d{4}-\\d{2}-\\d{2}|\\d{1,2}\\/\\d{1,2}\\/\\d{2,4}|\\d{1,2} [A-Z][a-z]{2,8} \\d{4}|[A-Z][a-z]{2,8} \\d{1,2}, \\d{4})\\b/g),
    currency: grab(/(?:[$£€]\\s?\\d[\\d,. ]*|\\b\\d[\\d,. ]*\\s?(?:USD|EUR|GBP|SAR|AED)\\b)/g),
    numbers: grab(/\\b\\d{1,3}(?:[.,]\\d{3})+(?:[.,]\\d+)?\\b/g)
  };
}"""


def emit(obj):
    print(MARKER)
    print(json.dumps(obj))


try:
    from playwright.sync_api import sync_playwright
except Exception as exc:  # noqa: BLE001
    emit({"fatal": "playwright-unavailable: %s: %s" % (type(exc).__name__, exc)})
    raise SystemExit(0)

AXE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js"
VIEWPORTS = {"mobile": (390, 844), "tablet": (820, 1180), "desktop": (1440, 900)}
FILL = {"email": "shipgate.tester@example.com", "password": "Str0ng!Passw0rd",
        "tel": "+15550123456", "number": "42", "url": "https://example.com",
        "date": "2026-01-15", "search": "test query", "text": "ship-gate test input"}
# A real browser clicking a control labelled "Delete account" / "Pay now" against a
# non-disposable target executes the irreversible action. High-precision denylist.
DESTRUCTIVE = re.compile(
    r"\b(delete|remove|destroy|deactivate|log\s*out|sign\s*out|logout|signout|pay|purchase|"
    r"checkout|charge|wipe|revoke|unsubscribe|terminate|delete\s*account|close\s*account|"
    r"approve|reject|transfer|publish|execute|send|confirm|archive|refund|finalize|"
    r"submit\s*order|cancel\s*order|return\s+to)\b", re.I)
SEL = "button, [role=button], input[type=submit], a[href^='javascript'], [onclick]"


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "x").lower())[:60].strip("-") or "x"


def find_local_axe(out):
    """bootstrap saves axe.min.js into <repo>/shipgate-workdir/. Search upward for it."""
    here = Path(out).resolve()
    cands = [here / "axe.min.js", here.parent / "axe.min.js"]
    for d in [here, *here.parents]:
        cands.append(d / "shipgate-workdir" / "axe.min.js")
        if d.name == "shipgate-workdir":
            cands.append(d / "axe.min.js")
    for c in cands:
        try:
            if c.exists():
                return c
        except OSError:
            continue
    return None


def metrics_of(page):
    try:
        nav = page.evaluate(
            "() => { const n = performance.getEntriesByType('navigation')[0];"
            " const p = performance.getEntriesByType('paint');"
            " const fcp = (p.find(e => e.name === 'first-contentful-paint') || {}).startTime;"
            " return n ? {ttfb: n.responseStart, dcl: n.domContentLoadedEventEnd,"
            " load: n.loadEventEnd, fcp: fcp || 0} : null; }")
    except Exception:
        nav = None
    try:
        lcp = page.evaluate(
            "() => new Promise(res => { let v = 0;"
            " try { const po = new PerformanceObserver(l => { for (const e of l.getEntries())"
            " v = e.startTime; }); po.observe({type: 'largest-contentful-paint',"
            " buffered: true}); } catch (e) {}"
            " setTimeout(() => res(v), 700); })")
    except Exception:
        lcp = 0
    out = {}
    if nav:
        for src, dst in (("ttfb", "ttfb_ms"), ("dcl", "dcl_ms"), ("load", "load_ms"),
                         ("fcp", "fcp_ms")):
            try:
                out[dst] = int(round(float(nav.get(src) or 0)))
            except (TypeError, ValueError):
                pass
    try:
        out["lcp_ms"] = int(round(float(lcp or 0)))
    except (TypeError, ValueError):
        out["lcp_ms"] = 0
    return out


def main():
    base = sys.argv[1]
    outdir = Path(sys.argv[2])
    max_pages = int(sys.argv[3])
    do_axe = sys.argv[4] == "1"
    allow_destructive = sys.argv[5] == "1"
    shots = outdir / "shots"
    shots.mkdir(parents=True, exist_ok=True)

    pages, interactions = [], []
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            emit({"fatal": "chromium-launch-failed: %s: %s" % (type(exc).__name__, exc)})
            return
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        console_errors, failed_reqs, fired = [], [], []
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("requestfailed",
                lambda r: failed_reqs.append("%s %s :: %s" % (r.method, r.url, r.failure)))
        page.on("response", lambda r: (
            fired.append("%s %s -> %s" % (r.request.method, r.url, r.status)),
            failed_reqs.append("%s %s -> %s" % (r.request.method, r.url, r.status))
            if r.status >= 400 else None))
        m = re.match(r"https?://[^/]+", base)
        origin = m.group(0) if m else base
        queue, seen = [base], set()
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            console_errors.clear()
            failed_reqs.clear()
            rec = {"url": url, "title": "", "load_error": None, "console_errors": [],
                   "failed_requests": [], "axe": None, "axe_error": None, "metrics": {},
                   "screenshots": {}, "style_census": None, "text_census": None,
                   "style_census_error": None, "text_census_error": None}
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception as exc:  # noqa: BLE001
                rec["load_error"] = "%s: %s" % (type(exc).__name__, exc)
                pages.append(rec)
                continue
            try:
                rec["title"] = page.title() or ""
            except Exception:
                rec["title"] = ""
            rec["metrics"] = metrics_of(page)
            pslug = slug(url.replace(origin, "") or "home")
            for vname, (w, h) in VIEWPORTS.items():
                try:
                    page.set_viewport_size({"width": w, "height": h})
                    time.sleep(0.4)
                    rel = "shots/%s__%s.png" % (pslug, vname)
                    page.screenshot(path=str(shots / ("%s__%s.png" % (pslug, vname))),
                                    full_page=True)
                    rec["screenshots"][vname] = rel
                except Exception:
                    rec["screenshots"][vname] = None
            page.set_viewport_size({"width": 1440, "height": 900})

            if do_axe:
                try:
                    local = find_local_axe(outdir)
                    if local is not None:
                        page.add_script_tag(content=local.read_text())
                    else:
                        page.add_script_tag(url=AXE_CDN)
                    res = page.evaluate(
                        "async () => { const r = await axe.run(); return {version:"
                        " (window.axe && window.axe.version) || 'unknown', violations:"
                        " r.violations.map(v => ({id: v.id, impact: v.impact, help: v.help,"
                        " nodes: v.nodes.length}))}; }")
                    rec["axe"] = res
                except Exception as exc:  # noqa: BLE001
                    # A layer that could not run is UNVERIFIED, not a violation. Emitting a
                    # pseudo-violation would both fake a11y signal and hide the outage.
                    rec["axe_error"] = "%s: %s" % (type(exc).__name__, exc)

            try:
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"):
                    if href.startswith(origin) and "#" not in href and href not in seen:
                        queue.append(href.split("?")[0])
            except Exception:
                pass

            # --- style and text inventory (G2 / G3) -------------------------------------
            #
            # BOUNDED AND SORTED, deliberately. A per-element dump would be enormous, would
            # differ between two runs over the same page, and would land inside the decision
            # digest — so what comes back is a COUNTED, sorted, capped census: which colours,
            # families, sizes and spacings appear and how often, and which labels appear on
            # which surface. Two runs over one page produce identical bytes.
            try:
                rec["style_census"] = page.evaluate(STYLE_CENSUS_JS)
            except Exception as exc:  # noqa: BLE001
                rec["style_census_error"] = "%s: %s" % (type(exc).__name__, exc)
            try:
                rec["text_census"] = page.evaluate(TEXT_CENSUS_JS)
            except Exception as exc:  # noqa: BLE001
                rec["text_census_error"] = "%s: %s" % (type(exc).__name__, exc)

            rec["console_errors"] = list(console_errors)
            rec["failed_requests"] = list(failed_reqs)
            pages.append(rec)

            # --- exercise interactive elements (re-query each time; the page may change) ---
            try:
                n = page.locator(SEL).count()
            except Exception:
                n = 0
            for i in range(min(n, 40)):
                try:
                    page.goto(url, wait_until="networkidle", timeout=20000)
                    # settle async rendering BEFORE the baseline, else late renders
                    # masquerade as click effects
                    prev = page.content()
                    for _ in range(6):
                        page.wait_for_timeout(400)
                        cur = page.content()
                        if cur == prev:
                            break
                        prev = cur
                    el = page.locator(SEL).nth(i)
                    if not el.is_visible():
                        continue
                    label = (el.inner_text(timeout=1000) or el.get_attribute("aria-label")
                             or "el-%d" % i).strip()[:50]
                    if not allow_destructive and DESTRUCTIVE.search(label):
                        interactions.append({
                            "page": url, "selector": "nth(%d)" % i, "label": label,
                            "fired_network": [], "dom_changed": False, "console_errors": [],
                            "screenshot": None,
                            "skipped": "destructive-label (allow_destructive to click)"})
                        continue
                    # count REAL mutations during the click window; content equality is
                    # polluted by async renders
                    page.evaluate(
                        "window.__sg_m=0; window.__sg_o&&window.__sg_o.disconnect();"
                        "window.__sg_o=new MutationObserver(ms=>window.__sg_m+=ms.length);"
                        "window.__sg_o.observe(document.body,{subtree:true,childList:true,"
                        "attributes:true,characterData:true})")
                    fired.clear()
                    console_errors.clear()
                    el.click(timeout=4000)
                    page.wait_for_timeout(1200)
                    mutations = int(page.evaluate("window.__sg_m") or 0)
                    shot = "%s__click__%s-%d.png" % (pslug, slug(label), i)
                    page.screenshot(path=str(shots / shot))
                    interactions.append({
                        "page": url, "selector": "nth(%d)" % i, "label": label,
                        "fired_network": list(fired), "dom_changed": mutations > 0,
                        "dom_mutations": mutations, "console_errors": list(console_errors),
                        "screenshot": "shots/%s" % shot})
                except Exception as exc:  # noqa: BLE001
                    interactions.append({
                        "page": url, "selector": "nth(%d)" % i, "label": "el-%d" % i,
                        "fired_network": [], "dom_changed": False,
                        "console_errors": ["interaction-error: %s" % exc], "screenshot": None})

            # --- fill + submit forms ---
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
                for fi in range(page.locator("form").count()):
                    form = page.locator("form").nth(fi)
                    # the form path honours the SAME destructive policy as the click path:
                    # <form action="/account/delete"><button>Delete</button></form>
                    if not allow_destructive:
                        try:
                            action = form.get_attribute("action") or ""
                            sublabel = ""
                            try:
                                sublabel = (form.locator(
                                    "button[type=submit], input[type=submit], button")
                                    .first.inner_text(timeout=800) or "")
                            except Exception:
                                pass
                            if DESTRUCTIVE.search(action) or DESTRUCTIVE.search(sublabel):
                                interactions.append({
                                    "page": url, "selector": "form#%d" % fi,
                                    "label": "form-%d" % fi, "fired_network": [],
                                    "dom_changed": False, "console_errors": [],
                                    "screenshot": None,
                                    "skipped": "destructive-form (allow_destructive to submit)"})
                                continue
                        except Exception:
                            pass
                    for inp in form.locator("input, textarea, select").all():
                        try:
                            t = (inp.get_attribute("type") or "text").lower()
                            if t in ("hidden", "checkbox", "radio", "file"):
                                continue
                            inp.fill(FILL.get(t, FILL["text"]), timeout=2000)
                        except Exception:
                            pass
                    fired.clear()
                    console_errors.clear()
                    before = page.content()
                    try:
                        form.locator("button[type=submit], input[type=submit], button") \
                            .first.click(timeout=4000)
                        page.wait_for_timeout(1500)
                        shot = "%s__form%d.png" % (pslug, fi)
                        page.screenshot(path=str(shots / shot))
                        interactions.append({
                            "page": url, "selector": "form#%d" % fi,
                            "label": "form-submit-%d" % fi, "fired_network": list(fired),
                            "dom_changed": page.content() != before,
                            "console_errors": list(console_errors),
                            "screenshot": "shots/%s" % shot})
                    except Exception:
                        pass
            except Exception:
                pass
        browser.close()

    emit({"pages": pages, "interactions": interactions,
          "viewports": ["%s %dx%d" % (k, v[0], v[1]) for k, v in VIEWPORTS.items()]})


main()
'''


def _parse_driver_output(stdout):
    if MARKER not in (stdout or ""):
        return None
    blob = stdout.split(MARKER, 1)[1].strip()
    # The driver prints exactly one JSON document after the marker; take the first line that
    # parses so target-emitted noise on stdout cannot corrupt the observation.
    for chunk in (blob, blob.splitlines()[0] if blob.splitlines() else ""):
        try:
            got = json.loads(chunk)
            if isinstance(got, dict):
                return got
        except Exception:
            continue
    return None


def _run_driver(ctx):
    """(data, error). Runs the browser driver once and caches its output in the workdir."""
    root = Path(ctx.run_area or ctx.repo).resolve()
    if not root.is_dir():
        return None, f"run area is not a directory: {root}"
    workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
    cache = workdir / "crawl.json"

    cached = ctx.option("crawl_payload")
    if isinstance(cached, dict):
        return cached, None
    if cache.exists():
        try:
            return json.loads(cache.read_text()), None
        except Exception:
            pass

    base = (ctx.option("base_url") or "").strip()
    if not base:
        return None, ("no base_url option was supplied, so no page was ever loaded; an "
                      "un-crawled UI is not a clean UI")

    driver = root / DRIVER_REL
    try:
        driver.parent.mkdir(parents=True, exist_ok=True)
        driver.write_text(DRIVER_SOURCE)
    except OSError as exc:
        return None, f"could not write the UI driver: {exc}"

    argv = [str(ctx.option("python", "python3")), DRIVER_REL, base, EVIDENCE_REL,
            str(int(ctx.option("max_pages", 15) or 15)),
            "1" if ctx.option("axe", True) else "0",
            "1" if ctx.option("allow_destructive") else "0"]
    try:
        res = ctx.adapter.run_target(
            argv=argv, cwd=root, timeout=int(ctx.option("crawl_timeout", 900) or 900),
            network=True, label="ui-crawl")
    except Exception as exc:  # noqa: BLE001 — a refused execution is evidence, not a crash
        return None, f"the UI driver could not be executed: {type(exc).__name__}: {exc}"

    data = _parse_driver_output(res.stdout)
    if data is None:
        tail = (res.stderr or res.stdout or "")[-400:]
        return None, (f"the UI driver produced no parseable observation "
                      f"(rc={res.returncode}, timedOut={res.timed_out}): {tail}")
    if data.get("fatal"):
        return None, str(data["fatal"])
    try:
        workdir.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data))
    except OSError:
        pass
    return data, None


class UiCrawlCollector(Collector):
    """Visit pages, screenshot them at three viewports and exercise every control."""

    kind = EvidenceKind.UI_CRAWL
    name = "ui-crawl"
    version = "4.2.4"

    def collect(self, ctx):
        data, err = _run_driver(ctx)
        if err:
            return self.error(ctx, err)

        raw_pages = [p for p in (data.get("pages") or []) if isinstance(p, dict)]
        viewports = [str(v) for v in (data.get("viewports") or [])]
        pages, errors = [], []
        for p in raw_pages:
            url = str(p.get("url") or "")
            if p.get("load_error"):
                errors.append(f"{url}: load error: {p['load_error']}")
                continue
            title = str(p.get("title") or "")
            shots = p.get("screenshots") or {}
            for vname in ("mobile", "tablet", "desktop"):
                pages.append({"url": url, "title": title,
                              "screenshot": (str(shots[vname]) if shots.get(vname) else None),
                              "viewport": vname})
            for e in (p.get("console_errors") or [])[:20]:
                errors.append(f"{url}: console: {str(e)[:200]}")
            for e in (p.get("failed_requests") or [])[:20]:
                errors.append(f"{url}: request: {str(e)[:200]}")

        interactions = [i for i in (data.get("interactions") or []) if isinstance(i, dict)]
        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        try:
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "interactions.json").write_text(json.dumps(interactions, indent=2))
        except OSError:
            pass

        visited = len([p for p in raw_pages if not p.get("load_error")])
        payload = {
            "pages": pages,
            "viewports": viewports or ["mobile", "tablet", "desktop"],
            "pagesVisited": visited,
            "errors": errors,
            "interactionsRecorded": len(interactions),
            "deadControls": sum(1 for i in interactions
                                if not i.get("fired_network") and not i.get("dom_changed")
                                and not i.get("skipped")),
            "skippedControls": sum(1 for i in interactions if i.get("skipped")),
            # Carried so the conformance and consistency collectors read ONE crawl rather
            # than driving the browser twice against a live target.
            "styleCensus": [{"url": str(p.get("url") or ""), "census": p.get("style_census")}
                            for p in raw_pages if p.get("style_census")],
            "textCensus": [{"url": str(p.get("url") or ""), "census": p.get("text_census")}
                           for p in raw_pages if p.get("text_census")],
        }
        if raw_pages and raw_pages[0].get("load_error"):
            # The base URL never rendered: this crawl proves nothing at all.
            return self.error(ctx, f"the base URL failed to load ({raw_pages[0]['load_error']}); "
                                   "this crawl is not evidence about any page", payload)
        if not visited:
            return self.error(ctx, "no page was successfully loaded", payload)

        uncovered = [f"page did not load: {p.get('url')}" for p in raw_pages if p.get("load_error")]
        return self.collected(ctx, payload,
                              note=f"{visited} page(s) crawled, {len(interactions)} interaction(s)",
                              uncovered=uncovered)


class A11yCollector(Collector):
    """axe-core violations for every crawled page."""

    kind = EvidenceKind.ACCESSIBILITY
    name = "accessibility"
    version = "4.2.4"

    def collect(self, ctx):
        data, err = _run_driver(ctx)
        if err:
            return self.error(ctx, err)

        violations, counts = [], {k: 0 for k in IMPACTS}
        scanned, failures, engine_version = 0, [], ""
        for p in (data.get("pages") or []):
            if not isinstance(p, dict) or p.get("load_error"):
                continue
            url = str(p.get("url") or "")
            axe = p.get("axe")
            if not isinstance(axe, dict):
                # A layer that could not run is UNVERIFIED, never a pass and never a
                # fabricated violation.
                failures.append(f"{url}: {p.get('axe_error') or 'axe did not run'}")
                continue
            scanned += 1
            engine_version = str(axe.get("version") or engine_version or "unknown")
            for v in (axe.get("violations") or []):
                if not isinstance(v, dict):
                    continue
                impact = str(v.get("impact") or "minor").lower()
                if impact not in IMPACTS:
                    # An unknown impact must not vanish; the most severe reading is the only
                    # fail-closed one.
                    impact = "critical"
                counts[impact] += 1
                violations.append({
                    "id": str(v.get("id") or "unknown"),
                    "impact": impact,
                    "help": str(v.get("help") or ""),
                    "nodes": int(v.get("nodes") or 0),
                    "url": url,
                })

        payload = {
            "violations": violations,
            "counts": counts,
            "pagesScanned": scanned,
            "engine": "axe-core",
            "engineVersion": engine_version or "unknown",
            "pagesNotScanned": failures,
        }
        if scanned == 0:
            return self.error(ctx, "the accessibility engine did not run on any page: "
                                   + ("; ".join(failures[:3]) or "no page was crawled"), payload)
        return self.collected(ctx, payload,
                              note=f"{scanned} page(s) scanned, {len(violations)} violation(s)",
                              uncovered=[f"a11y not scanned: {f}" for f in failures])


class PerfCollector(Collector):
    """Navigation-timing and largest-contentful-paint metrics for the crawled pages.

    Every metric is emitted as an INTEGER millisecond value: the canonical form rejects
    floats, and a platform-dependent dtoa in a decision digest is not acceptable.
    """

    kind = EvidenceKind.PERFORMANCE
    name = "performance"
    version = "4.2.4"

    def collect(self, ctx):
        data, err = _run_driver(ctx)
        if err:
            return self.error(ctx, err)

        worst, per_page, scanned = {}, [], 0
        for p in (data.get("pages") or []):
            if not isinstance(p, dict) or p.get("load_error"):
                continue
            metrics = p.get("metrics")
            if not isinstance(metrics, dict) or not metrics:
                continue
            clean = {}
            for k, v in metrics.items():
                if not isinstance(k, str) or not re.match(r"^[a-z_]+_ms$", k):
                    continue
                try:
                    clean[k] = int(round(float(v)))
                except (TypeError, ValueError):
                    continue
            if not clean:
                continue
            scanned += 1
            per_page.append({"url": str(p.get("url") or ""), "metrics": clean})
            for k, v in clean.items():
                worst[k] = max(worst.get(k, 0), v)

        payload = {"metrics": worst, "pagesScanned": scanned, "tool": "playwright/web-vitals",
                   "perPage": per_page}
        if not worst:
            return self.error(ctx, "no performance metric could be measured on any page", payload)
        return self.collected(ctx, payload,
                              note=f"{scanned} page(s) measured; worst-case metrics reported")
