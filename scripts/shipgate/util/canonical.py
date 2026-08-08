"""Canonical JSON serialisation.

The decision digest is a consumer contract: two runs that reach the same semantic conclusion
over the same inputs MUST produce byte-identical canonical bytes, on any supported platform,
regardless of dict insertion order or float formatting.

Rules (deliberately narrower than RFC 8785 — we reject rather than coerce):
  * objects: keys sorted by UTF-16 code-unit order (what JSON.stringify + Array.sort gives),
    which for the ASCII key space we use is identical to codepoint order;
  * no insignificant whitespace;
  * separators are exactly ',' and ':';
  * strings escaped with the minimal JSON escape set, non-ASCII emitted raw as UTF-8;
  * integers emitted bare; floats are REJECTED (a decision must never carry a value whose
    textual form depends on the platform's dtoa). Callers round to int or format to str first;
  * NaN / Infinity / -0.0 REJECTED;
  * non-JSON types REJECTED — no silent str() coercion, which would let two different objects
    canonicalise identically.
"""
import hashlib
import json

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(TypeError):
    """A value cannot be canonicalised deterministically. Always fatal — never coerced."""


def _esc(s):
    out = ['"']
    for ch in s:
        e = _ESCAPES.get(ch)
        if e is not None:
            out.append(e)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _emit(obj, out, path):
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, int):
        out.append(str(obj))
    elif isinstance(obj, float):
        raise CanonicalizationError(
            f"float at {path or '$'}: floats are not canonicalisable; use an int or a "
            f"pre-formatted string (got {obj!r})")
    elif isinstance(obj, str):
        out.append(_esc(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, v in enumerate(obj):
            if i:
                out.append(",")
            _emit(v, out, f"{path}[{i}]")
        out.append("]")
    elif isinstance(obj, dict):
        keys = []
        for k in obj:
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string object key at {path or '$'}: {k!r}")
            keys.append(k)
        keys.sort(key=lambda s: s.encode("utf-16-be"))
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            out.append(_esc(k))
            out.append(":")
            _emit(obj[k], out, f"{path}.{k}")
        out.append("}")
    else:
        raise CanonicalizationError(
            f"non-JSON type at {path or '$'}: {type(obj).__name__}")
    return out


def canonical_json(obj):
    """Canonical JSON *text* (str)."""
    return "".join(_emit(obj, [], ""))


def canonical_bytes(obj):
    """Canonical JSON *bytes* (UTF-8). This is what gets hashed and what gets signed."""
    return canonical_json(obj).encode("utf-8")


def digest_of(obj):
    """sha256 hex of the canonical bytes of `obj`."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def loads_strict(text):
    """json.loads that rejects duplicate object keys.

    A duplicate key is the classic parser-differential: Python keeps the last, some parsers
    keep the first. Anything we then re-canonicalise would not round-trip. Fail closed.
    """
    def _hook(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                raise CanonicalizationError(f"duplicate object key in input: {k!r}")
            seen.add(k)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=_hook)
