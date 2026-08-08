"""DESIGN_CONFORMANCE (G2) and CROSS_SURFACE (G3) — the mechanical floors of two judgement
phases.

Both read the census the UI crawl already captured, so neither drives the browser a second
time against a live target. Both are bounded, sorted and counted, so two runs over one build
produce identical bytes and the results can sit inside a decision digest.

WHAT G2 IS FOR. "Does the implementation use the design system?" is checkable. Parse the
tokens — palette, spacing scale, type scale, font families, radii — and compare them against
the values the pages ACTUALLY RENDERED WITH. A colour that is not in the palette, a spacing
value that is not on the scale, a font nobody chose: those are facts, and a design review
that misses them was not a design review. What is NOT checkable is whether the result looks
good, and this collector does not pretend otherwise.

WHAT G3 IS FOR. Consistency across surfaces is comparison, which is what programs are for.
The same action labelled "Delete" on one screen and "Remove" on another; three date formats
in one product; a currency rendered two ways; a term of art that drifts between pages. A
human notices maybe half of these and only after enough exposure. What is NOT checkable is
whether an inconsistency MATTERS — a marketing page and an admin console may legitimately
speak differently — so every finding names both surfaces and leaves the judgement where it
belongs.

FAIL-FIRST ADMISSION, both directions, every run, before either looks at your pages. Each
family runs over an in-memory CONFORMANT census, which it must leave clean, and a SEEDED one
carrying one instance of each defect class, every one of which it must flag. A checker that
flags nothing and a checker that flags everything are equally useless — and on a design
system the second is the likelier failure, because "not exactly on the scale" describes most
of the web. Failing either makes the evidence ERROR and the gate fails closed.
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..models.evidence import EvidenceKind
from .base import Collector

# ---------------------------------------------------------------------------------------
# shared parsing
# ---------------------------------------------------------------------------------------

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_RGB = re.compile(r"^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)\s*(?:[,/]\s*([\d.%]+))?\s*\)$")
_PX = re.compile(r"^(-?[\d.]+)px$")

#: Values that are not a design decision and must never be reported as off-palette:
#: the transparent default, the two ends of the greyscale, and the browser's own inherit.
_NEUTRAL_COLOURS = frozenset({"transparent", "inherit", "initial", "currentcolor", "none",
                              "rgba(0, 0, 0, 0)"})


def normalise_colour(value):
    """`#FFF`, `#ffffff`, `rgb(255,255,255)` and `rgba(255,255,255,1)` are one colour.

    Comparing raw strings would report a palette violation every time a browser serialised a
    token differently from the way the design system wrote it — a checker that fires on
    notation rather than on colour, which is the stuck alarm the admission check exists to
    catch.
    """
    v = str(value or "").strip().lower()
    if not v or v in _NEUTRAL_COLOURS:
        return ""
    if _HEX.match(v):
        h = v[1:]
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        a = round(int(h[6:8], 16) / 255, 3) if len(h) == 8 else 1.0
        return f"{r},{g},{b},{a:g}"
    m = _RGB.match(v)
    if m:
        r, g, b = (int(round(float(m.group(i)))) for i in (1, 2, 3))
        raw_a = m.group(4)
        if raw_a is None:
            a = 1.0
        elif raw_a.endswith("%"):
            a = float(raw_a[:-1]) / 100
        else:
            a = float(raw_a)
        return f"{r},{g},{b},{round(a, 3):g}"
    return v


def px(value):
    """A pixel value as a float, or None. `0px` and `normal` are not spacing decisions."""
    m = _PX.match(str(value or "").strip())
    if not m:
        return None
    f = float(m.group(1))
    return None if f == 0 else abs(f)


def normalise_font(value):
    return str(value or "").split(",")[0].strip().strip("'\"").lower()


# ---------------------------------------------------------------------------------------
# G2 — design-token conformance
# ---------------------------------------------------------------------------------------

#: How far off the scale a value may be and still count as on it. Sub-pixel rendering and
#: rem-to-px rounding routinely produce 15.984px for a 16px token; calling that a violation
#: would bury the real ones.
SPACING_TOLERANCE_PX = 0.75

#: A value must appear at least this many times before it is reported. One stray element with
#: a hand-written margin is a nit; forty of them is a design system nobody is using.
MIN_OCCURRENCES = 2


def check_conformance(tokens, censuses) -> Dict[str, Any]:
    """Diff the rendered census against the declared tokens. Pure."""
    palette = {normalise_colour(c) for c in _as_list(tokens.get("colors"))
               + _as_list(tokens.get("colours"))}
    palette.discard("")
    scale = sorted({v for v in (px(s) for s in _as_list(tokens.get("spacing"))) if v})
    type_scale = sorted({v for v in (px(s) for s in _as_list(tokens.get("fontSizes"))) if v})
    families = {normalise_font(f) for f in _as_list(tokens.get("fontFamilies"))}
    families.discard("")
    radii = sorted({v for v in (px(s) for s in _as_list(tokens.get("radii"))) if v})

    findings: List[Dict[str, Any]] = []
    for entry in censuses:
        url = str(entry.get("url") or "")
        c = entry.get("census") or {}
        if palette:
            for dim in ("color", "background"):
                for item in c.get(dim) or []:
                    val, count = normalise_colour(item.get("value")), int(item.get("count") or 0)
                    if val and count >= MIN_OCCURRENCES and val not in palette:
                        findings.append(_f("off_palette", url, dim, item.get("value"), count,
                                           "not in the declared palette"))
        if scale:
            for item in c.get("spacing") or []:
                val, count = px(item.get("value")), int(item.get("count") or 0)
                if val and count >= MIN_OCCURRENCES and not _on_scale(val, scale):
                    findings.append(_f("off_spacing_scale", url, "spacing",
                                       item.get("value"), count,
                                       f"not on the spacing scale {_fmt(scale)}"))
        if type_scale:
            for item in c.get("fontSize") or []:
                val, count = px(item.get("value")), int(item.get("count") or 0)
                if val and count >= MIN_OCCURRENCES and not _on_scale(val, type_scale):
                    findings.append(_f("off_type_scale", url, "fontSize", item.get("value"),
                                       count, f"not on the type scale {_fmt(type_scale)}"))
        if families:
            for item in c.get("fontFamily") or []:
                val, count = normalise_font(item.get("value")), int(item.get("count") or 0)
                if val and count >= MIN_OCCURRENCES and val not in families:
                    findings.append(_f("off_font_family", url, "fontFamily",
                                       item.get("value"), count,
                                       f"not a declared family ({', '.join(sorted(families))})"))
        if radii:
            for item in c.get("borderRadius") or []:
                val, count = px(item.get("value")), int(item.get("count") or 0)
                if val and count >= MIN_OCCURRENCES and not _on_scale(val, radii):
                    findings.append(_f("off_radius_scale", url, "borderRadius",
                                       item.get("value"), count,
                                       f"not on the radius scale {_fmt(radii)}"))
    findings.sort(key=lambda f: (f["kind"], f["url"], str(f["value"])))
    return {"findings": findings,
            "tokens": {"colors": sorted(palette), "spacing": scale, "fontSizes": type_scale,
                       "fontFamilies": sorted(families), "radii": radii},
            "dimensionsChecked": sorted(
                d for d, on in (("colour", bool(palette)), ("spacing", bool(scale)),
                                ("typeScale", bool(type_scale)),
                                ("fontFamily", bool(families)), ("radius", bool(radii))) if on),
            "counts": _by_kind(findings)}


def _on_scale(value, scale):
    return any(abs(value - s) <= SPACING_TOLERANCE_PX for s in scale)


def _f(kind, url, dimension, value, count, detail):
    return {"kind": kind, "url": url, "dimension": dimension, "value": str(value),
            "occurrences": count, "detail": detail}


def _fmt(scale):
    return "[" + ", ".join(f"{s:g}px" for s in scale) + "]"


# ---------------------------------------------------------------------------------------
# G3 — cross-surface consistency
# ---------------------------------------------------------------------------------------

#: Date shapes, in the order they are tried. A product that renders two of these is
#: inconsistent whatever an individual page thinks.
_DATE_SHAPES = (
    ("iso", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("slashed", re.compile(r"^\d{1,2}/\d{1,2}/\d{2,4}$")),
    ("long-dmy", re.compile(r"^\d{1,2} [A-Z][a-z]{2,8} \d{4}$")),
    ("long-mdy", re.compile(r"^[A-Z][a-z]{2,8} \d{1,2}, \d{4}$")),
)

#: Pairs that mean the same thing to a user and should not both appear on one product's
#: controls. Kept small and defensible — a big synonym table would produce arguments, not
#: findings.
_SYNONYMS = (
    ("delete", "remove"), ("sign in", "log in"), ("sign out", "log out"),
    ("sign up", "register"), ("edit", "modify"), ("cancel", "discard"),
    ("save", "submit"), ("search", "find"), ("settings", "preferences"),
)

_ACTION_NOISE = re.compile(r"^[\s\W\d]*$")


def check_cross_surface(censuses) -> Dict[str, Any]:
    """Compare surfaces against each other. Pure."""
    surfaces = [(str(e.get("url") or ""), e.get("census") or {}) for e in censuses]
    findings: List[Dict[str, Any]] = []

    # 1. DATE FORMAT. More than one shape across the product.
    shapes: Dict[str, List[str]] = {}
    for url, c in surfaces:
        for text in c.get("dates") or []:
            name = _date_shape(text)
            if name:
                shapes.setdefault(name, [])
                if url not in shapes[name]:
                    shapes[name].append(url)
    if len(shapes) > 1:
        findings.append({
            "kind": "date_format_divergence", "detail":
            "the product renders dates in " + str(len(shapes)) + " different formats: "
            + "; ".join(f"{k} on {', '.join(v[:3])}" for k, v in sorted(shapes.items())),
            "surfaces": sorted({u for v in shapes.values() for u in v}),
            "values": sorted(shapes)})

    # 2. CURRENCY. Two renderings of money in one product.
    styles: Dict[str, List[str]] = {}
    for url, c in surfaces:
        for text in c.get("currency") or []:
            name = _currency_style(text)
            if name:
                styles.setdefault(name, [])
                if url not in styles[name]:
                    styles[name].append(url)
    if len(styles) > 1:
        findings.append({
            "kind": "currency_format_divergence", "detail":
            "money is rendered in " + str(len(styles)) + " different styles: "
            + "; ".join(f"{k} on {', '.join(v[:3])}" for k, v in sorted(styles.items())),
            "surfaces": sorted({u for v in styles.values() for u in v}),
            "values": sorted(styles)})

    # 3. THOUSANDS SEPARATOR. `1,234.5` and `1.234,5` in one product.
    seps: Dict[str, List[str]] = {}
    for url, c in surfaces:
        for text in c.get("numbers") or []:
            name = _separator(text)
            if name:
                seps.setdefault(name, [])
                if url not in seps[name]:
                    seps[name].append(url)
    if len(seps) > 1:
        findings.append({
            "kind": "number_format_divergence",
            "detail": "numbers use " + " and ".join(sorted(seps)) + " as separators",
            "surfaces": sorted({u for v in seps.values() for u in v}),
            "values": sorted(seps)})

    # 4. SYNONYMOUS ACTION LABELS. One action, two words.
    where: Dict[str, List[str]] = {}
    for url, c in surfaces:
        for label in (c.get("actions") or []) + (c.get("nav") or []):
            key = str(label).strip().lower()
            if not key or _ACTION_NOISE.match(key):
                continue
            where.setdefault(key, [])
            if url not in where[key]:
                where[key].append(url)
    for a, b in _SYNONYMS:
        ua, ub = _labels_matching(where, a), _labels_matching(where, b)
        if ua and ub and ua != ub:
            findings.append({
                "kind": "synonymous_action_labels",
                "detail": f"the same action is labelled {a!r} on {', '.join(sorted(ua)[:3])} "
                          f"and {b!r} on {', '.join(sorted(ub)[:3])}",
                "surfaces": sorted(ua | ub), "values": [a, b]})

    # 5. NAVIGATION DRIFT. A nav entry that exists on some surfaces and not others.
    navs = {url: {str(n).strip().lower() for n in (c.get("nav") or []) if str(n).strip()}
            for url, c in surfaces}
    present = {u: n for u, n in navs.items() if n}
    if len(present) > 1:
        everywhere = set.intersection(*present.values())
        anywhere = set.union(*present.values())
        drifting = sorted(anywhere - everywhere)
        if drifting and len(drifting) <= max(3, len(anywhere) // 2):
            findings.append({
                "kind": "navigation_drift",
                "detail": "navigation entries present on some surfaces and absent on others: "
                          + ", ".join(drifting[:6]),
                "surfaces": sorted(present), "values": drifting[:12]})

    findings.sort(key=lambda f: (f["kind"], str(f.get("values"))))
    return {"findings": findings, "surfaces": sorted(u for u, _ in surfaces),
            "counts": _by_kind(findings)}


def _labels_matching(where, word):
    out = set()
    for label, urls in where.items():
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", label):
            out.update(urls)
    return out


def _date_shape(text):
    t = str(text).strip()
    for name, rx in _DATE_SHAPES:
        if rx.match(t):
            return name
    return ""


def _currency_style(text):
    t = str(text).strip()
    if re.match(r"^[$£€]\s?\d", t):
        return "symbol-prefix" + ("-spaced" if re.match(r"^[$£€]\s\d", t) else "")
    if re.search(r"\d\s?(USD|EUR|GBP|SAR|AED)$", t):
        return "code-suffix"
    return ""


def _separator(text):
    t = str(text).strip()
    if re.match(r"^\d{1,3}(,\d{3})+(\.\d+)?$", t):
        return "comma-thousands"
    if re.match(r"^\d{1,3}(\.\d{3})+(,\d+)?$", t):
        return "dot-thousands"
    if re.match(r"^\d{1,3}( \d{3})+([.,]\d+)?$", t):
        return "space-thousands"
    return ""


def _by_kind(findings):
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1
    counts["total"] = len(findings)
    return counts


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, dict):
        return list(v.values())
    return list(v) if isinstance(v, list) else [v]


# =======================================================================================
# fail-first admission
# =======================================================================================

_REF_TOKENS = {"colors": ["#0B0C0E", "#FFFFFF", "#2563EB"],
               "spacing": ["4px", "8px", "16px", "24px", "32px"],
               "fontSizes": ["12px", "14px", "16px", "20px", "32px"],
               "fontFamilies": ["Inter", "IBM Plex Mono"],
               "radii": ["4px", "8px"]}


def _census(colours, spacings, sizes, fonts, radii=("8px",)):
    def rows(vals):
        return [{"value": v, "count": 9} for v in vals]
    return {"elementsCounted": 40, "color": rows(colours), "background": rows(["#FFFFFF"]),
            "spacing": rows(spacings), "fontSize": rows(sizes), "fontFamily": rows(fonts),
            "borderRadius": rows(radii)}


_G2_GOOD = [{"url": "/", "census": _census(
    # Deliberately in three different notations for the SAME tokens: a checker that compares
    # raw strings fires here, and that is a false alarm on a conformant page.
    ["rgb(11, 12, 14)", "#2563eb", "rgba(37, 99, 235, 1)"],
    ["8px", "16px", "15.984px"], ["16px", "32px"], ["Inter", '"Inter"'])}]

_G2_SEEDED = [{"url": "/", "census": _census(
    ["#0B0C0E", "#FF00AA"],            # off_palette
    ["8px", "13px"],                   # off_spacing_scale
    ["16px", "17px"],                  # off_type_scale
    ["Inter", "Comic Sans MS"],        # off_font_family
    ["8px", "3px"])}]                  # off_radius_scale

_G2_MUST_CATCH = ("off_palette", "off_spacing_scale", "off_type_scale", "off_font_family",
                  "off_radius_scale")

_G3_GOOD = [
    {"url": "/", "census": {"actions": ["Delete", "Save"], "nav": ["Home", "Orders"],
                            "dates": ["2026-08-06"], "currency": ["$1,200.00"],
                            "numbers": ["1,200"], "headings": ["Home"]}},
    {"url": "/orders", "census": {"actions": ["Delete", "Save"], "nav": ["Home", "Orders"],
                                  "dates": ["2026-01-02"], "currency": ["$9.50"],
                                  "numbers": ["12,000"], "headings": ["Orders"]}},
]

_G3_SEEDED = [
    {"url": "/", "census": {"actions": ["Delete", "Save"], "nav": ["Home", "Orders"],
                            "dates": ["2026-08-06"], "currency": ["$1,200.00"],
                            "numbers": ["1,200"], "headings": ["Home"]}},
    {"url": "/orders", "census": {"actions": ["Remove", "Save"],          # synonymous labels
                                  "nav": ["Home", "Orders", "Reports"],   # navigation_drift
                                  "dates": ["02/01/2026"],                # date divergence
                                  "currency": ["9.50 USD"],               # currency divergence
                                  "numbers": ["1.200"],                   # number divergence
                                  "headings": ["Orders"]}},
]

_G3_MUST_CATCH = ("date_format_divergence", "currency_format_divergence",
                  "number_format_divergence", "synonymous_action_labels",
                  "navigation_drift")


def _admit(label, run_good, run_seeded, must_catch):
    clean = run_good()
    seeded = run_seeded()
    caught = sorted({f["kind"] for f in seeded["findings"]})
    missed = [k for k in must_catch if k not in caught]
    false_alarms = sorted({f["kind"] for f in clean["findings"]})
    admitted = not missed and not false_alarms
    return {"admitted": admitted, "defectClasses": list(must_catch), "caught": caught,
            "missed": missed, "falseAlarmsOnConformantReference": false_alarms,
            "detail": (f"{label}: every seeded defect class was caught and none fired on the "
                       f"conformant reference" if admitted else
                       "; ".join(filter(None, [
                           f"{label} MISSED {', '.join(missed)}" if missed else "",
                           f"{label} false alarms: {false_alarms}" if false_alarms else ""])))}


def conformance_admission():
    return _admit("design conformance",
                  lambda: check_conformance(_REF_TOKENS, _G2_GOOD),
                  lambda: check_conformance(_REF_TOKENS, _G2_SEEDED),
                  _G2_MUST_CATCH)


def cross_surface_admission():
    return _admit("cross-surface consistency",
                  lambda: check_cross_surface(_G3_GOOD),
                  lambda: check_cross_surface(_G3_SEEDED),
                  _G3_MUST_CATCH)


# =======================================================================================
# collectors
# =======================================================================================


def _crawl_census(ctx, key):
    """(censuses, problem). Reads the census the UI crawl already captured.

    Two sources, in the same order the crawl itself uses. `crawl_payload` is the inline
    driver observation an operator or a test supplies instead of running a browser; when it
    is set the crawl never writes `crawl.json`, so a reader that only looked on disk would
    report "the crawl must run first" about a crawl that had just run. That is the exact
    shape of defect the audit found three times: a producer and a consumer that were each
    tested alone and never against each other.
    """
    doc = ctx.option("crawl_payload")
    if not isinstance(doc, dict):
        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        path = workdir / "crawl.json"
        if not path.exists():
            return [], (f"no crawl.json in {workdir.name}; this collector reads the census the "
                        f"UI crawl captured rather than driving the browser a second time, so "
                        f"the crawl must run first")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [], f"crawl.json is unreadable ({type(exc).__name__}: {exc})"
        if not isinstance(doc, dict):
            return [], "crawl.json is not an object"
    rows = []
    for page in (doc.get("pages") or []):
        if isinstance(page, dict) and page.get(key):
            rows.append({"url": str(page.get("url") or ""), "census": page[key]})
    if not rows:
        return [], (f"the crawl captured no {key}; this build of the driver may predate it, "
                    f"or every page failed to render")
    return rows, ""


class DesignConformanceCollector(Collector):
    """Phase G2's mechanical floor: declared tokens versus what the pages rendered with.

    Options: `design_tokens_file` (default `<workdir>/design-tokens.json`), `design_tokens`
    (the object inline).
    """

    kind = EvidenceKind.DESIGN_CONFORMANCE
    name = "design-conformance"
    version = "4.2.4"

    def collect(self, ctx):
        adm = conformance_admission()
        if not adm["admitted"]:
            return self.error(ctx, "the design-conformance checker FAILED its own fail-first "
                                   f"admission and was not run: {adm['detail']}",
                              payload={"admission": adm})
        tokens, note = self._tokens(ctx)
        if tokens is None:
            return self.absent(
                ctx, f"no design tokens were declared ({note}); Phase G2 coverage stays "
                     f"UNCOLLECTED. Template: assets/templates/design-tokens.json.template")
        censuses, problem = _crawl_census(ctx, "style_census")
        if problem:
            return self.error(ctx, problem, payload={"admission": adm})

        result = check_conformance(tokens, censuses)
        if not result["dimensionsChecked"]:
            return self.error(ctx, "the token file declares no palette, spacing scale, type "
                                   "scale, font family or radius scale, so nothing could be "
                                   "compared; an empty token set is not a conformant one",
                              payload={"admission": adm, "tokens": result["tokens"]})
        payload = {"admission": adm, "tokenSource": note, "tokens": result["tokens"],
                   "dimensionsChecked": result["dimensionsChecked"],
                   "surfaces": sorted({c["url"] for c in censuses}),
                   "findings": result["findings"], "counts": result["counts"]}
        return self.collected(
            ctx, payload,
            note=(f"{result['counts']['total']} conformance finding(s) across "
                  f"{len(censuses)} surface(s), {len(result['dimensionsChecked'])} "
                  f"dimension(s) checked"))

    def _tokens(self, ctx):
        inline = ctx.option("design_tokens")
        if isinstance(inline, dict):
            return inline, "supplied inline via --options-file"
        root = Path(ctx.run_area or ctx.repo).resolve()
        workdir = Path(ctx.workdir) if ctx.workdir else root / "shipgate-workdir"
        path = Path(ctx.option("design_tokens_file") or (workdir / "design-tokens.json"))
        if not path.exists():
            return None, f"no {path.name}"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"{path.name} is unreadable: {type(exc).__name__}: {exc}")
        if not isinstance(doc, dict):
            raise ValueError(f"{path.name} is not an object")
        return (doc.get("tokens") if isinstance(doc.get("tokens"), dict) else doc), str(path.name)


class CrossSurfaceCollector(Collector):
    """Phase G3's mechanical floor: one action one label, one product one date format."""

    kind = EvidenceKind.CROSS_SURFACE
    name = "cross-surface"
    version = "4.2.4"

    def collect(self, ctx):
        adm = cross_surface_admission()
        if not adm["admitted"]:
            return self.error(ctx, "the cross-surface checker FAILED its own fail-first "
                                   f"admission and was not run: {adm['detail']}",
                              payload={"admission": adm})
        censuses, problem = _crawl_census(ctx, "text_census")
        if problem:
            return self.absent(ctx, f"{problem}; Phase G3 coverage stays UNCOLLECTED")
        if len(censuses) < 2:
            # One surface cannot be inconsistent with itself. ABSENT rather than a clean
            # pass, because "we compared one page against nothing" is not consistency
            # evidence and must not read as any.
            return self.absent(
                ctx, f"only {len(censuses)} surface was crawled; cross-surface consistency "
                     f"needs at least two. Phase G3 coverage stays UNCOLLECTED")
        result = check_cross_surface(censuses)
        payload = {"admission": adm, "surfaces": result["surfaces"],
                   "findings": result["findings"], "counts": result["counts"]}
        return self.collected(
            ctx, payload,
            note=(f"{result['counts']['total']} consistency finding(s) across "
                  f"{len(result['surfaces'])} surface(s)"))


def describe() -> str:
    return "\n".join([
        "DESIGN_CONFORMANCE (G2) — declared tokens versus what the pages rendered with.",
        f"  Checked: {', '.join(_G2_MUST_CATCH)}.",
        f"  Tolerance {SPACING_TOLERANCE_PX}px on every scale, and a value must appear",
        f"  {MIN_OCCURRENCES}+ times before it is reported — sub-pixel rounding and one",
        "  stray margin are not design-system violations.",
        "  NOT checked: whether it looks good. That stays judgement.",
        "",
        "CROSS_SURFACE (G3) — surfaces compared against each other.",
        f"  Checked: {', '.join(_G3_MUST_CATCH)}.",
        "  NOT checked: whether an inconsistency MATTERS — a marketing page and an admin",
        "  console may legitimately differ — so every finding names both surfaces.",
    ])
