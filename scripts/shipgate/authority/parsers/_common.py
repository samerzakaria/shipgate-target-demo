"""Shared parsing primitives. Every parser in this package goes through these.

The rules that make the parsers boring and safe:

  * DECODE EXPLICITLY. Four of the real captures arrived UTF-16LE with a BOM (PowerShell
    redirection does that), so BOM handling is a first-class requirement, not a fixup. Any
    byte sequence we cannot decode exactly is `AUT_OUTPUT_SHAPE_UNKNOWN` — never "decode with
    errors='replace' and hope".
  * PARSE STRICTLY. `util.canonical.loads_strict` rejects duplicate object keys; a parser
    differential is a signature-bypass primitive, not a curiosity.
  * BOUND THE INPUT. A tool that printed a gigabyte is not evidence.
  * FAIL CLOSED. Every function returns a `ParseResult`; none raises for bad input. There is
    no code path that turns an unrecognised shape into a success.
"""
import base64
import binascii
import dataclasses
import hashlib
import re
from typing import Any, Optional, Tuple

from ...models import reasons as R
from ...util.canonical import CanonicalizationError, loads_strict

#: Nothing a trust tool legitimately prints is bigger than this.
MAX_INPUT_BYTES = 4 * 1024 * 1024


@dataclasses.dataclass(frozen=True)
class ParseResult:
    """The outcome of parsing one tool output. `ok=False` always carries a reason code."""
    ok: bool
    shape_id: str
    data: Optional[Any] = None
    reason_code: Optional[str] = None
    detail: str = ""

    def __post_init__(self):
        if self.ok and self.reason_code is not None:
            raise ValueError("a successful ParseResult may not carry a reason code")
        if not self.ok and self.reason_code not in R.AUTHORITY_EMITTABLE:
            raise ValueError(
                f"parse failure must carry an AUT_ reason code, got {self.reason_code!r}")

    def to_json(self):
        return {"ok": self.ok, "shapeId": self.shape_id, "reasonCode": self.reason_code,
                "detail": self.detail}


def ok(shape_id, data):
    return ParseResult(True, shape_id, data)


def fail(shape_id, reason_code, detail, data=None):
    """A refusal. `data` may carry parsed CONTEXT (never a positive finding) so a caller can
    produce a sharper second-stage refusal instead of a vaguer first-stage one."""
    return ParseResult(False, shape_id, data, R.require_valid(reason_code), detail)


def unknown(shape_id, detail):
    """The default refusal: we do not recognise this, so it is not evidence."""
    return fail(shape_id, R.AUT_OUTPUT_SHAPE_UNKNOWN, detail)


# ---------------------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------------------

_BOMS = (
    (b"\xef\xbb\xbf", "utf-8-sig", "UTF-8 BOM"),
    (b"\xff\xfe\x00\x00", "utf-32-le", "UTF-32LE BOM"),
    (b"\x00\x00\xfe\xff", "utf-32-be", "UTF-32BE BOM"),
    (b"\xff\xfe", "utf-16", "UTF-16LE BOM"),
    (b"\xfe\xff", "utf-16", "UTF-16BE BOM"),
)


def decode_text(raw, shape_id):
    """bytes|str -> (ParseResult, text). BOM-aware, strict, size-bounded.

    Returns (None, text) on success so callers can `res, text = decode_text(...)` and check
    `if res is not None: return res`.
    """
    if isinstance(raw, str):
        text = raw
        if len(text.encode("utf-8", "surrogatepass")) > MAX_INPUT_BYTES:
            return unknown(shape_id, f"input exceeds {MAX_INPUT_BYTES} bytes"), None
        return None, text.lstrip("﻿")
    if not isinstance(raw, (bytes, bytearray)):
        return unknown(shape_id, f"expected bytes or str, got {type(raw).__name__}"), None
    if len(raw) > MAX_INPUT_BYTES:
        return unknown(shape_id, f"input exceeds {MAX_INPUT_BYTES} bytes "
                                 f"({len(raw)} bytes)"), None
    data = bytes(raw)
    encoding, label = "utf-8", "no BOM (UTF-8 assumed)"
    for bom, enc, name in _BOMS:
        if data.startswith(bom):
            encoding, label = enc, name
            break
    try:
        text = data.decode(encoding)
    except (UnicodeDecodeError, LookupError) as exc:
        return unknown(shape_id, f"undecodable output ({label}): {exc}"), None
    text = text.lstrip("﻿")
    if "\x00" in text:
        return unknown(shape_id, "output contains NUL bytes after decoding "
                                 f"({label}); refusing to guess an encoding"), None
    return None, text


def load_json(raw, shape_id):
    """bytes|str -> (ParseResult|None, obj). Strict: BOM-aware, duplicate keys rejected."""
    res, text = decode_text(raw, shape_id)
    if res is not None:
        return res, None
    if not text.strip():
        return unknown(shape_id, "empty output"), None
    try:
        doc = loads_strict(text)
    except CanonicalizationError as exc:
        return unknown(shape_id, f"refusing ambiguous JSON: {exc}"), None
    except ValueError as exc:
        return unknown(shape_id, f"malformed JSON: {exc}"), None
    return None, doc


# ---------------------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------------------

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def parse_semver(text):
    """'v3.1.2' / '3.1.2-rc1' -> (3, 1, 2). None when unparseable — never guessed."""
    if not isinstance(text, str):
        return None
    m = _SEMVER.match(text.strip())
    if not m:
        return None
    return tuple(int(g) for g in m.groups())


@dataclasses.dataclass(frozen=True)
class VersionGate:
    """An inclusive-lower, exclusive-upper supported range, plus the version we validated.

    A version outside the range is `AUT_TOOL_VERSION_UNSUPPORTED`. An ABSENT or unparseable
    version is ALSO unsupported: "we do not know what produced this" is not a green light.
    """
    tool: str
    minimum: Tuple[int, int, int]
    below: Tuple[int, int, int]
    validated: str

    def check(self, version_text):
        if version_text is None or version_text == "":
            return (False, R.AUT_TOOL_VERSION_UNSUPPORTED,
                    f"{self.tool} version was not supplied; this kit refuses to parse output "
                    "from an unidentified tool version")
        parsed = parse_semver(version_text)
        if parsed is None:
            return (False, R.AUT_TOOL_VERSION_UNSUPPORTED,
                    f"unparseable {self.tool} version {version_text!r}")
        if parsed < self.minimum or parsed >= self.below:
            return (False, R.AUT_TOOL_VERSION_UNSUPPORTED,
                    f"{self.tool} {version_text} is outside the supported range "
                    f">={_v(self.minimum)},<{_v(self.below)} "
                    f"(validated against {self.validated})")
        return True, None, ""

    def describe(self):
        return (f"{self.tool} >={_v(self.minimum)},<{_v(self.below)} "
                f"(validated: {self.validated})")


def _v(t):
    return ".".join(str(x) for x in t)


# ---------------------------------------------------------------------------------------
# Bytes, base64, hex, DER
# ---------------------------------------------------------------------------------------

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def b64decode_strict(text, what, shape_id):
    """Strict base64 -> (ParseResult|None, bytes). Rejects whitespace/alt-alphabet padding
    games, which are a classic way to smuggle two readings of one field."""
    if not isinstance(text, str) or not text:
        return unknown(shape_id, f"{what}: expected a non-empty base64 string"), None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        return unknown(shape_id, f"{what}: not strict base64 ({exc})"), None
    if base64.b64encode(raw).decode("ascii") != text:
        return unknown(shape_id, f"{what}: base64 is not canonical (re-encoding differs)"), None
    return None, raw


def hex64(text):
    return isinstance(text, str) and bool(_HEX64.match(text))


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def is_der_ecdsa_signature(raw):
    """Structural DER check for SEQUENCE { INTEGER r, INTEGER s }.

    Deliberately structural only. This kit does NOT implement signature verification — that
    is cosign's job and re-implementing ECDSA here would be exactly the 'cryptographic
    infrastructure beyond scope' the release forbids. What this proves is that a field
    claiming to be a signature is a well-formed one, so a truncated or corrupted blob is
    caught at parse time instead of being passed along as opaque evidence.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return False, "too short to be a DER signature"
    data = bytes(raw)
    if data[0] != 0x30:
        return False, f"expected DER SEQUENCE (0x30), got 0x{data[0]:02x}"
    body, err = _der_len(data, 1)
    if err:
        return False, err
    offset, length = body
    if offset + length != len(data):
        return False, (f"DER length {length} does not cover the payload "
                       f"({len(data) - offset} bytes remain)")
    pos = offset
    for name in ("r", "s"):
        if pos >= len(data) or data[pos] != 0x02:
            return False, f"expected INTEGER for {name}"
        got, err = _der_len(data, pos + 1)
        if err:
            return False, err
        pos = got[0] + got[1]
    if pos != len(data):
        return False, "trailing bytes after the (r, s) pair"
    return True, ""


def is_der_sequence(raw):
    """Structural check that `raw` is a single, complete DER SEQUENCE (RFC3161 token, cert)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 4:
        return False, "too short to be a DER structure"
    data = bytes(raw)
    if data[0] != 0x30:
        return False, f"expected DER SEQUENCE (0x30), got 0x{data[0]:02x}"
    got, err = _der_len(data, 1)
    if err:
        return False, err
    if got[0] + got[1] != len(data):
        return False, "DER length does not cover the payload"
    return True, ""


def _der_len(data, pos):
    """-> ((content_offset, length), error)."""
    if pos >= len(data):
        return None, "truncated DER length"
    first = data[pos]
    if first < 0x80:
        return (pos + 1, first), None
    count = first & 0x7F
    if count == 0 or count > 4 or pos + 1 + count > len(data):
        return None, "unsupported or truncated DER long-form length"
    length = int.from_bytes(data[pos + 1:pos + 1 + count], "big")
    return (pos + 1 + count, length), None


__all__ = [
    "MAX_INPUT_BYTES", "ParseResult", "VersionGate", "b64decode_strict", "decode_text",
    "fail", "hex64", "is_der_ecdsa_signature", "is_der_sequence", "load_json", "ok",
    "parse_semver", "sha256", "unknown",
]
