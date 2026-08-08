"""The output-shape registry — the thing that makes "we actually saw this" checkable.

A parser in this kit is only allowed to succeed on a shape that has been VALIDATED against a
REAL capture. That is not a comment: `SHAPES.json` records, per shape, the tool, version,
command, schema file, capture file and the capture's sha256, and this loader RE-HASHES the
capture at load time. A shape whose capture is missing, altered, or absent is BLOCKED, and a
BLOCKED shape makes its parser return `AUT_OUTPUT_SHAPE_UNKNOWN` no matter how plausible the
input looks.

Two consequences are deliberate:

  * A hand-authored sample can never be promoted to evidence. Synthetic fixtures live in
    `tests_data/` under a `SYNTHETIC-ADVERSARIAL__` filename prefix, and the loader refuses
    to mark a shape VALIDATED from anywhere except `captures/normalized/`.
  * Shapes we could not capture (keyless cosign bundle, protected GitHub environment, the
    GitHub Actions OIDC claim set) are implemented, schema'd, and permanently refused until
    somebody registers a real capture. Fail closed, visibly, with a reason.

Also here: a deliberately small JSON Schema subset validator. The kit has no third-party
dependencies, so the schemas would otherwise be decoration. Only the keywords the schemas
actually use are implemented, and an unknown keyword is an ERROR, never a silent pass.
"""
import hashlib
import json
import os
import re
from typing import Any, Dict, Optional, Tuple

from ..models import reasons as R
from ..util.canonical import CanonicalizationError, loads_strict

# `capturestore` is imported LAZILY, inside the two functions that use it. A module-level
# import would put it in `sys.modules` before `python -m shipgate.authority.capturestore`
# could execute it as `__main__` — runpy then emits a RuntimeWarning about unpredictable
# behaviour on the kit's own documented inspection command. Both call sites are cold (nothing
# on the VERIFIED path reads a capture), so the deferred import costs nothing.

_HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(_HERE, "schemas")
CAPTURE_DIR = os.path.join(_HERE, "captures")
TESTS_DATA_DIR = os.path.join(_HERE, "tests_data")
MANIFEST_PATH = os.path.join(SCHEMA_DIR, "SHAPES.json")
#: Every schema in one file. Sixteen loose schema files cost sixteen of the skill's 200-file
#: budget to say what one object says; the `schemaFile` key in SHAPES.json is now a key into
#: this bundle rather than a path, and an entry naming a schema that is not in it gets an
#: empty schema — which fails validation closed, the same as an unreadable file did.
SCHEMA_BUNDLE_PATH = os.path.join(SCHEMA_DIR, "SCHEMAS.json")
_SCHEMA_BUNDLE: Optional[Dict[str, Any]] = None


def __getattr__(name):
    """`NORMALIZED_DIR` / `RAW_DIR`, materialized on first use.

    They used to be plain paths into the package. The corpus now lives in one archive
    (see `capturestore`), so a caller that genuinely needs a DIRECTORY — the CI and
    independent adapters take an `evidenceDir` of real files, because that is what they
    take in production — gets a temporary extraction instead. Lazy through the module
    hook rather than eager at import: nothing on the VERIFIED path reads a capture, and
    importing this module must not touch the disk.
    """
    if name in ("NORMALIZED_DIR", "RAW_DIR"):
        from . import capturestore
        return capturestore.variant_dir(
            capturestore.NORMALIZED if name == "NORMALIZED_DIR" else capturestore.RAW)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def schema_bundle() -> Dict[str, Any]:
    """The parsed schema bundle. An unreadable bundle means every schema is empty."""
    global _SCHEMA_BUNDLE
    if _SCHEMA_BUNDLE is None:
        try:
            with open(SCHEMA_BUNDLE_PATH, "r", encoding="utf-8") as fh:
                doc = loads_strict(fh.read())
            schemas = doc.get("schemas") if isinstance(doc, dict) else None
            _SCHEMA_BUNDLE = schemas if isinstance(schemas, dict) else {}
        except (OSError, ValueError, CanonicalizationError):
            _SCHEMA_BUNDLE = {}
    return _SCHEMA_BUNDLE


#: The only prefix a hand-authored fixture may have. Enforced by `fixtures.load_synthetic`.
SYNTHETIC_PREFIX = "SYNTHETIC-ADVERSARIAL__"

VALIDATED = "VALIDATED"
BLOCKED = "BLOCKED"


class ShapeEntry:
    """One registered output shape. Immutable in practice; never mutated after load."""

    __slots__ = ("shape_id", "tool", "tool_version", "command", "schema_file", "capture_file",
                 "capture_sha256", "declared_status", "status", "provenance", "note",
                 "blocked_reason", "additional_captures", "shape_validated",
                 "binding_validated", "binding_note", "version_tier", "version_constraint",
                 "version_provenance", "version_corroboration", "tool_release_date",
                 "runner_environment",
                 "cosign_provenance", "gh_provenance", "produced_by", "blocked_evidence",
                 "blocked_evidence_problem", "_schema")

    #: Retired vocabulary. `UNSTATED` used to mean "a capture exists and nobody said what made
    #: it". Every entry that carried it is now RUNNER-RESOLVED — we know the install mechanism
    #: (sigstore/cosign-installer@v3, the runner's ambient gh) and we know it does not pin a
    #: version. That is a DIFFERENT epistemic state, and collapsing the two would lose the only
    #: part of it an adopter can act on. A manifest that still says UNSTATED is a manifest whose
    #: provenance work is unfinished, so `selfcheck` asserts none does.
    RETIRED_VERSION_STATES = frozenset({"UNSTATED"})

    def __init__(self, shape_id, raw):
        self.shape_id = shape_id
        self.tool = raw.get("tool") or ""
        self.tool_version = raw.get("toolVersion") or ""
        # VERSION TIER. Not decoration: `versionConstraint` is null wherever no version can
        # honestly be pinned, and a null constraint means the gate must NOT apply a range —
        # inventing a plausible number to make the column uniform is the fabrication this
        # registry exists to prevent. See SHAPES.json `versionTiers`.
        self.version_tier = raw.get("versionTier") or ""
        self.version_constraint = raw.get("versionConstraint")
        self.version_provenance = raw.get("versionProvenance") or ""
        # CORROBORATION. A link to something OUTSIDE this repository that independently
        # records the claimed version. It raises how checkable an assertion is; it does
        # NOT raise the tier, because corroborating that a version exists is not the same
        # as watching the binary that produced this capture print its own version. Only
        # OPERATOR-ASSERTED-CONFIRMED entries carry one, and selfcheck asserts that.
        self.version_corroboration = raw.get("versionCorroboration") or ""
        self.tool_release_date = raw.get("toolReleaseDate") or ""
        self.runner_environment = raw.get("runnerEnvironment") or ""
        self.cosign_provenance = raw.get("cosignProvenance") or ""
        self.gh_provenance = raw.get("ghProvenance") or ""
        self.produced_by = raw.get("producedBy") or ""
        # Evidence that a BLOCKED shape cannot be captured. Digest-pinned and re-hashed like
        # any capture, but it validates NOTHING and can never promote an entry: it is a record
        # of impossibility, and it lives on the blocked side of the fence on purpose.
        self.blocked_evidence = raw.get("blockedEvidence") or None
        self.blocked_evidence_problem = ""
        self.command = raw.get("command") or ""
        self.schema_file = raw.get("schemaFile") or ""
        self.capture_file = raw.get("captureFile")
        self.capture_sha256 = raw.get("captureSha256")
        self.additional_captures = list(raw.get("additionalCaptures") or ())
        self.declared_status = raw.get("status") or BLOCKED
        self.provenance = raw.get("provenance") or "NONE"
        self.note = raw.get("note") or ""
        self.blocked_reason = raw.get("blockedReason") or ""
        # VALIDATION SCOPE. A capture can prove the SHAPE without proving that the identity
        # inside it binds to anything — a sanitised fixture is the obvious case. Recording
        # the two separately stops "we have a capture" from being read as "and it all checks
        # out". Defaults: shape validated when the entry is, binding NOT claimed.
        self.shape_validated = bool(raw.get("shapeValidated", True))
        self.binding_validated = bool(raw.get("bindingValidated", False))
        self.binding_note = raw.get("bindingNote") or ""
        self.status = BLOCKED
        self._schema = None

    # -- integrity ---------------------------------------------------------------------
    def _resolve(self):
        """Decide the EFFECTIVE status. Never trusts the declared one on its own."""
        self._resolve_blocked_evidence()
        self._resolve_status()
        if self.status != VALIDATED and self.blocked_evidence_problem:
            self.blocked_reason = (self.blocked_reason + " [" + self.blocked_evidence_problem
                                   + "]").strip()

    def _resolve_status(self):
        if self.declared_status != VALIDATED:
            self.status = BLOCKED
            if not self.blocked_reason:
                self.blocked_reason = "declared BLOCKED in SHAPES.json"
            return
        if self.provenance != "REAL_CAPTURE":
            self.status = BLOCKED
            self.blocked_reason = (
                f"claims {VALIDATED} with provenance={self.provenance!r}; only REAL_CAPTURE "
                "may validate a shape")
            return
        if not self.capture_file:
            self.status = BLOCKED
            self.blocked_reason = f"claims {VALIDATED} with no capture file"
            return
        for name, expected in self._pinned_captures():
            problem = _verify_capture(name, expected)
            if problem:
                self.status = BLOCKED
                self.blocked_reason = problem
                return
        if not self.shape_validated:
            self.status = BLOCKED
            self.blocked_reason = ("entry sets shapeValidated=false; a shape whose own "
                                   "manifest does not claim shape validation is not validated")
            return
        self.status = VALIDATED

    def _pinned_captures(self):
        """Every capture this entry pins, primary first. All are re-hashed at load."""
        yield self.capture_file, self.capture_sha256
        for extra in self.additional_captures:
            if isinstance(extra, dict):
                yield extra.get("captureFile"), extra.get("captureSha256")

    def _resolve_blocked_evidence(self):
        """Re-hash the impossibility evidence, if any. Never changes the status.

        A missing or altered evidence file must NOT unblock anything (nothing here can), but it
        must not silently vanish either: a blocked shape whose stated reason has lost its
        receipt is a shape whose reason is now hearsay, so the problem is appended to
        `blocked_reason` where anyone reading the refusal will see it.
        """
        if not isinstance(self.blocked_evidence, dict):
            self.blocked_evidence = None
            return
        problem = _verify_capture(self.blocked_evidence.get("captureFile"),
                                  self.blocked_evidence.get("captureSha256"))
        if problem:
            self.blocked_evidence_problem = f"blockedEvidence unverified: {problem}"

    # -- schema ------------------------------------------------------------------------
    def schema(self):
        if self._schema is None:
            found = schema_bundle().get(self.schema_file)
            self._schema = found if isinstance(found, dict) else {}
        return self._schema

    def to_json(self):
        return {
            "shapeId": self.shape_id, "tool": self.tool, "toolVersion": self.tool_version,
            "versionTier": self.version_tier, "versionConstraint": self.version_constraint,
            "versionProvenance": self.version_provenance,
            "versionCorroboration": self.version_corroboration,
            "toolReleaseDate": self.tool_release_date,
            "runnerEnvironment": self.runner_environment,
            "cosignProvenance": self.cosign_provenance, "ghProvenance": self.gh_provenance,
            "producedBy": self.produced_by,
            "command": self.command, "schemaFile": self.schema_file,
            "captureFile": self.capture_file,
            "additionalCaptures": [e.get("captureFile") for e in self.additional_captures
                                   if isinstance(e, dict)],
            "status": self.status,
            "declaredStatus": self.declared_status, "provenance": self.provenance,
            "shapeValidated": self.shape_validated,
            "bindingValidated": self.binding_validated, "bindingNote": self.binding_note,
            "blockedEvidence": (self.blocked_evidence.get("captureFile")
                                if self.blocked_evidence else None),
            "blockedEvidenceProblem": self.blocked_evidence_problem,
            "blockedReason": self.blocked_reason, "note": self.note,
        }

    def version_is_gateable(self):
        """True when a version RANGE may be enforced for this shape.

        False for RUNNER-RESOLVED, SERVER-API and NOT-CAPTURED, whose `versionConstraint` is
        null. Callers must not substitute a default: "no constraint" is the finding.
        """
        return bool(self.version_constraint)


class ShapeRegistry:
    """The loaded manifest. Constructing one never raises — an unreadable manifest means
    EVERY shape is blocked, which is the safe direction."""

    def __init__(self, manifest_path=MANIFEST_PATH):
        self.manifest_path = manifest_path
        self.load_error = ""
        self.entries: Dict[str, ShapeEntry] = {}
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                doc = loads_strict(fh.read())
        except (OSError, ValueError, CanonicalizationError) as exc:
            self.load_error = f"shape manifest unreadable ({exc})"
            return
        if not isinstance(doc, dict) or not isinstance(doc.get("shapes"), dict):
            self.load_error = "shape manifest has no 'shapes' object"
            return
        for shape_id, raw in doc["shapes"].items():
            if not isinstance(raw, dict):
                continue
            entry = ShapeEntry(shape_id, raw)
            entry._resolve()
            self.entries[shape_id] = entry

    # -- queries -----------------------------------------------------------------------
    def get(self, shape_id) -> Optional[ShapeEntry]:
        return self.entries.get(shape_id)

    def status(self, shape_id) -> str:
        entry = self.entries.get(shape_id)
        return entry.status if entry else BLOCKED

    def validated_ids(self):
        return tuple(sorted(k for k, v in self.entries.items() if v.status == VALIDATED))

    def blocked_ids(self):
        return tuple(sorted(k for k, v in self.entries.items() if v.status != VALIDATED))

    def require_validated(self, shape_id) -> Tuple[bool, Optional[str], str]:
        """(ok, reason_code, detail). The single gate every parser calls before succeeding."""
        entry = self.entries.get(shape_id)
        if entry is None:
            return (False, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                    f"shape {shape_id!r} is not registered in SHAPES.json"
                    + (f" ({self.load_error})" if self.load_error else ""))
        if entry.status != VALIDATED:
            return (False, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                    f"shape {shape_id!r} is BLOCKED: {entry.blocked_reason or 'not validated'}. "
                    "Register a real capture before this shape can be trusted.")
        return (True, None, "")

    def first_validated(self, *shape_ids):
        """The first of `shape_ids` that is VALIDATED, else None.

        For a shape captured MORE THAN ONCE. Two captures of one serialisation from two
        producing versions are redundancy, not two contracts: a parser needs one of them intact,
        and tampering with either must not take the shape offline. Order is significance order —
        pass the canonical id first.
        """
        for shape_id in shape_ids:
            entry = self.entries.get(shape_id)
            if entry is not None and entry.status == VALIDATED:
                return shape_id
        return None

    def require_any_validated(self, *shape_ids) -> Tuple[Optional[str], Optional[str], str]:
        """(shape_id, reason_code, detail). Like `require_validated`, over a redundant set."""
        chosen = self.first_validated(*shape_ids)
        if chosen is not None:
            return chosen, None, ""
        parts = []
        for shape_id in shape_ids:
            entry = self.entries.get(shape_id)
            parts.append(f"{shape_id}: "
                         + (entry.blocked_reason or "not validated" if entry
                            else "not registered in SHAPES.json"))
        return (None, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                "every registered capture of this shape is BLOCKED — "
                + "; ".join(parts)
                + ". Register a real capture before this shape can be trusted.")

    def version_tiers(self):
        """{tier -> [shape_id]}. The provenance situations the corpus is actually in."""
        out: Dict[str, list] = {}
        for shape_id in sorted(self.entries):
            out.setdefault(self.entries[shape_id].version_tier or "(unset)", []).append(shape_id)
        return out

    def retired_version_states(self):
        """Shape ids still carrying a RETIRED version vocabulary word. Must be empty."""
        return tuple(shape_id for shape_id in sorted(self.entries)
                     if self.entries[shape_id].tool_version
                     in ShapeEntry.RETIRED_VERSION_STATES
                     or self.entries[shape_id].version_tier
                     in ShapeEntry.RETIRED_VERSION_STATES)

    def matrix(self):
        return [self.entries[k].to_json() for k in sorted(self.entries)]


def _verify_capture(name, expected_sha256):
    """'' when the capture is in the NORMALIZED corpus and hashes to the pin.

    The variant argument is hard-coded and must stay that way. It is the validation fence:
    a shape may be validated from `normalized/` and from nowhere else, and because the
    corpus is a read-only archive keyed by variant, `read(NORMALIZED, ...)` cannot reach a
    `raw/` entry or a hand-authored `tests_data/` one even if the name collides.
    """
    if not name:
        return "an entry claims VALIDATED with a capture entry that names no file"
    from . import capturestore
    try:
        data = capturestore.read(capturestore.NORMALIZED, name)
    except capturestore.CaptureStoreError as exc:
        return f"capture {name!r} unreadable: {exc}"
    got = hashlib.sha256(data).hexdigest()
    if got != expected_sha256:
        return (f"capture {name!r} digest mismatch: manifest="
                f"{str(expected_sha256)[:16]}… file={got[:16]}…")
    return ""


_REGISTRY: Optional[ShapeRegistry] = None


def registry() -> ShapeRegistry:
    """The process-wide registry. Loaded once, from the shipped manifest only."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = ShapeRegistry()
    return _REGISTRY


# =======================================================================================
# Minimal JSON Schema validation (draft-07 subset, stdlib only).
# =======================================================================================

_SUPPORTED_KEYWORDS = frozenset({
    "$schema", "$id", "title", "description", "type", "properties", "required",
    "additionalProperties", "items", "enum", "const", "pattern", "minItems", "maxItems",
    "minLength", "minimum", "maximum", "minProperties", "patternProperties",
})

_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})


class SchemaError(ValueError):
    """The schema itself is unusable. Always fatal — a broken schema must not pass data."""


def _matches(value, name):
    # `bool` is an `int` in Python; a JSON Schema "integer" must never accept `true`.
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, (list, tuple))
    return isinstance(value, str)


def _check_type(value, expected, path, errs):
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        if name not in _TYPES:
            raise SchemaError(f"unsupported type {name!r} at {path}")
        if _matches(value, name):
            return True
    errs.append(f"{path}: expected type {expected!r}, got {type(value).__name__}")
    return False


def _validate(value, schema, path, errs):
    if not isinstance(schema, dict):
        raise SchemaError(f"schema at {path} is not an object")
    unknown = set(schema) - _SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaError(f"unsupported schema keywords at {path}: {sorted(unknown)}")

    if "type" in schema and not _check_type(value, schema["type"], path, errs):
        return
    if "const" in schema and value != schema["const"]:
        errs.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not in enum {schema['enum']!r}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: does not match pattern {schema['pattern']!r}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than minLength {schema['minLength']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: {value} > maximum {schema['maximum']}")
    if isinstance(value, (list, tuple)):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append(f"{path}: {len(value)} items < minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errs.append(f"{path}: {len(value)} items > maxItems {schema['maxItems']}")
        if "items" in schema:
            for i, item in enumerate(value):
                _validate(item, schema["items"], f"{path}[{i}]", errs)
    if isinstance(value, dict):
        for key in schema.get("required", ()):
            if key not in value:
                errs.append(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errs.append(f"{path}: {len(value)} properties < minProperties "
                        f"{schema['minProperties']}")
        for key, sub in value.items():
            if key in props:
                _validate(sub, props[key], f"{path}.{key}", errs)
                continue
            matched = False
            for pat, sub_schema in patterns.items():
                if re.search(pat, key):
                    _validate(sub, sub_schema, f"{path}.{key}", errs)
                    matched = True
            if matched:
                continue
            extra = schema.get("additionalProperties", True)
            if extra is False:
                errs.append(f"{path}: unexpected property {key!r}")
            elif isinstance(extra, dict):
                _validate(sub, extra, f"{path}.{key}", errs)


def validate(value: Any, schema: Dict[str, Any]) -> Tuple[bool, str]:
    """(ok, detail). Raises SchemaError only when the SCHEMA is broken, never on bad data."""
    errs = []
    _validate(value, schema, "$", errs)
    if errs:
        return False, "; ".join(errs[:6]) + (f" (+{len(errs) - 6} more)" if len(errs) > 6 else "")
    return True, ""


def validate_shape(value: Any, shape_id: str, reg: Optional[ShapeRegistry] = None):
    """Validate `value` against the schema registered for `shape_id`.

    Returns (ok, reason_code, detail). A blocked shape fails here first, so a caller cannot
    accidentally accept an unvalidated shape by validating only the JSON Schema.
    """
    reg = reg or registry()
    ok, code, detail = reg.require_validated(shape_id)
    if not ok:
        return False, code, detail
    entry = reg.get(shape_id)
    schema = entry.schema()
    if not schema:
        return (False, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                f"schema file {entry.schema_file!r} for {shape_id!r} is missing or unreadable")
    try:
        good, why = validate(value, schema)
    except SchemaError as exc:
        return False, R.AUT_OUTPUT_SHAPE_UNKNOWN, f"schema {entry.schema_file!r} is broken: {exc}"
    if not good:
        return (False, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                f"output does not match the validated {shape_id!r} shape: {why}")
    return True, None, ""


def validate_shape_any(value: Any, shape_ids, reg: Optional[ShapeRegistry] = None):
    """`validate_shape` over a REDUNDANT set of ids. Returns (ok, code, detail, chosen_id).

    Used where one serialisation has been captured more than once — the keyed sigstore bundle
    v0.3 (cosign v3.1.2 and v3.1.3) and the two verify-blob texts. All ids in a set must share a
    schema; `selfcheck` asserts that, because a set whose members disagreed about the schema
    would silently pick whichever capture happened to be intact.
    """
    reg = reg or registry()
    chosen, code, detail = reg.require_any_validated(*shape_ids)
    if chosen is None:
        return False, code, detail, None
    ok, code, detail = validate_shape(value, chosen, reg)
    return ok, code, detail, chosen


__all__ = [
    "BLOCKED", "CAPTURE_DIR", "MANIFEST_PATH", "NORMALIZED_DIR", "RAW_DIR", "SCHEMA_DIR",
    "SYNTHETIC_PREFIX", "SchemaError", "ShapeEntry", "ShapeRegistry", "TESTS_DATA_DIR",
    "VALIDATED", "registry", "validate", "validate_shape", "validate_shape_any",
]
