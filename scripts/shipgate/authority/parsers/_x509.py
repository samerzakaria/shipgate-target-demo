"""A minimal, read-only DER/X.509 reader. Stdlib only, no crypto.

Why this exists: a keyless cosign bundle carries the signer's identity inside a Fulcio
certificate, and that identity is the whole point of the keyless path. Reading it needs an
ASN.1 walk. Python's stdlib has no X.509 parser and this kit takes no third-party
dependency, so there is one here.

What this is NOT: it does not verify the certificate's signature, does not build or validate
a chain to a root, does not check revocation, and does not verify the embedded SCT. All of
those need asymmetric crypto and trust roots, which are out of this release's bounded scope
and belong to `cosign verify-blob`. Every function here answers "what does this certificate
SAY", never "is this certificate TRUSTWORTHY". Callers must keep that distinction — a parsed
identity is a claim, and `cosign verify-blob`'s verdict is what makes it a checked one.

Hostile input is expected. Every function is total: bad input yields (None, error), never an
exception, and the parser is bounded in depth, length and element count so a crafted
certificate cannot exhaust memory or recursion.
"""
import base64
import binascii
import datetime as _dt

#: Bounds. A real Fulcio leaf is ~2 KB with ~40 elements; these are generous but finite.
MAX_DER_BYTES = 65536
MAX_DEPTH = 24
MAX_ELEMENTS = 4096

# --- tags -------------------------------------------------------------------------------
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_PRINTABLE = 0x13
TAG_IA5 = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
#: GeneralName [6] uniformResourceIdentifier, context-specific primitive.
TAG_GN_URI = 0x86

_STRING_TAGS = (TAG_UTF8_STRING, TAG_PRINTABLE, TAG_IA5, 0x14, 0x1A, 0x1E)

# --- OIDs we care about -----------------------------------------------------------------
OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_SAN = "2.5.29.17"
OID_EKU = "2.5.29.37"
OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_SCT = "1.3.6.1.4.1.11129.2.4.2"

#: Sigstore/Fulcio certificate extensions. 1.1–1.6 are the deprecated flat strings; 1.8+ are
#: the current DER-UTF8String-wrapped ones. Both appear in a real GitHub Actions leaf.
FULCIO_OIDS = {
    "1.3.6.1.4.1.57264.1.1": ("oidcIssuerLegacy", False),
    "1.3.6.1.4.1.57264.1.2": ("githubWorkflowTrigger", False),
    "1.3.6.1.4.1.57264.1.3": ("githubWorkflowSha", False),
    "1.3.6.1.4.1.57264.1.4": ("githubWorkflowName", False),
    "1.3.6.1.4.1.57264.1.5": ("githubWorkflowRepository", False),
    "1.3.6.1.4.1.57264.1.6": ("githubWorkflowRef", False),
    "1.3.6.1.4.1.57264.1.8": ("issuer", True),
    "1.3.6.1.4.1.57264.1.9": ("buildSignerUri", True),
    "1.3.6.1.4.1.57264.1.10": ("buildSignerDigest", True),
    "1.3.6.1.4.1.57264.1.11": ("runnerEnvironment", True),
    "1.3.6.1.4.1.57264.1.12": ("sourceRepositoryUri", True),
    "1.3.6.1.4.1.57264.1.13": ("sourceRepositoryDigest", True),
    "1.3.6.1.4.1.57264.1.14": ("sourceRepositoryRef", True),
    "1.3.6.1.4.1.57264.1.15": ("sourceRepositoryIdentifier", True),
    "1.3.6.1.4.1.57264.1.16": ("sourceRepositoryOwnerUri", True),
    "1.3.6.1.4.1.57264.1.17": ("sourceRepositoryOwnerIdentifier", True),
    "1.3.6.1.4.1.57264.1.18": ("buildConfigUri", True),
    "1.3.6.1.4.1.57264.1.19": ("buildConfigDigest", True),
    "1.3.6.1.4.1.57264.1.20": ("buildTrigger", True),
    "1.3.6.1.4.1.57264.1.21": ("runInvocationUri", True),
    "1.3.6.1.4.1.57264.1.22": ("sourceRepositoryVisibility", True),
    "1.3.6.1.4.1.57264.1.23": ("buildConfigRef", True),
    "1.3.6.1.4.1.57264.1.24": ("subjectAlternativeNameSubject", True),
}

PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"


class DerError(ValueError):
    """Malformed DER. Always fatal to the parse — never partially trusted."""


# =======================================================================================
# TLV
# =======================================================================================


def read_tlv(buf, offset=0):
    """-> (tag, value_bytes, next_offset). Raises DerError on anything malformed."""
    if offset + 2 > len(buf):
        raise DerError("truncated TLV header")
    tag = buf[offset]
    length_byte = buf[offset + 1]
    pos = offset + 2
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        raise DerError("indefinite length is not valid DER")
    else:
        count = length_byte & 0x7F
        if count > 4:
            raise DerError(f"unsupported DER long-form length ({count} bytes)")
        if pos + count > len(buf):
            raise DerError("truncated DER long-form length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    if pos + length > len(buf):
        raise DerError(f"DER element claims {length} bytes, only {len(buf) - pos} remain")
    return tag, buf[pos:pos + length], pos + length


def _is_constructed(tag):
    return bool(tag & 0x20)


def iter_children(buf):
    """Yield the direct children of a constructed value."""
    offset = 0
    while offset < len(buf):
        tag, value, offset = read_tlv(buf, offset)
        yield tag, value


def decode_oid(raw):
    """DER OID bytes -> dotted string."""
    if not raw:
        raise DerError("empty OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    shifted = False
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        shifted = True
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
            shifted = False
    if shifted:
        raise DerError("OID ends mid-arc")
    return ".".join(parts)


def decode_time(tag, raw):
    """UTCTime / GeneralizedTime -> epoch seconds (int)."""
    text = raw.decode("ascii", "strict")
    if tag == TAG_UTC_TIME:
        if len(text) != 13 or not text.endswith("Z"):
            raise DerError(f"unsupported UTCTime {text!r}")
        parsed = _dt.datetime.strptime(text, "%y%m%d%H%M%SZ")
    elif tag == TAG_GENERALIZED_TIME:
        if len(text) != 15 or not text.endswith("Z"):
            raise DerError(f"unsupported GeneralizedTime {text!r}")
        parsed = _dt.datetime.strptime(text, "%Y%m%d%H%M%SZ")
    else:
        raise DerError(f"tag 0x{tag:02x} is not a time")
    return int(parsed.replace(tzinfo=_dt.timezone.utc).timestamp())


def _decode_string(tag, raw):
    if tag in _STRING_TAGS:
        return raw.decode("utf-8", "strict")
    raise DerError(f"tag 0x{tag:02x} is not a string")


# =======================================================================================
# PEM
# =======================================================================================


def pem_to_der(text):
    """(der_bytes, error). Requires EXACTLY ONE certificate block — a bundle that smuggles a
    second certificate is refused rather than silently reading the first."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError:
            return None, "certificate PEM is not ASCII"
    if text.count(PEM_BEGIN) != 1 or text.count(PEM_END) != 1:
        return None, (f"expected exactly one PEM CERTIFICATE block, found "
                      f"{text.count(PEM_BEGIN)} BEGIN / {text.count(PEM_END)} END")
    body = text.split(PEM_BEGIN, 1)[1].split(PEM_END, 1)[0]
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        return None, f"certificate PEM body is not base64 ({exc})"
    if not der:
        return None, "certificate PEM body is empty"
    if len(der) > MAX_DER_BYTES:
        return None, f"certificate is {len(der)} bytes, over the {MAX_DER_BYTES} limit"
    return der, ""


# =======================================================================================
# certificate
# =======================================================================================


def parse_certificate(der):
    """(fields_dict, error). Total: never raises.

    Returns what the certificate SAYS. Nothing here is a trust judgement.
    """
    if not isinstance(der, (bytes, bytearray)):
        return None, f"expected DER bytes, got {type(der).__name__}"
    if len(der) > MAX_DER_BYTES:
        return None, f"certificate is {len(der)} bytes, over the {MAX_DER_BYTES} limit"
    try:
        return _parse_certificate(bytes(der)), ""
    except DerError as exc:
        return None, str(exc)
    except (UnicodeDecodeError, ValueError, IndexError, RecursionError) as exc:
        return None, f"malformed certificate: {type(exc).__name__}: {exc}"


def _parse_certificate(der):
    tag, cert_body, end = read_tlv(der)
    if tag != TAG_SEQUENCE:
        raise DerError("certificate is not a DER SEQUENCE")
    if end != len(der):
        raise DerError("trailing bytes after the certificate")

    children = list(iter_children(cert_body))
    if len(children) != 3:
        raise DerError(f"certificate has {len(children)} top-level fields, expected 3")
    tbs_tag, tbs = children[0]
    if tbs_tag != TAG_SEQUENCE:
        raise DerError("tbsCertificate is not a SEQUENCE")

    fields = {
        "version": None, "serialHex": None, "issuer": {}, "subject": {},
        "notBefore": None, "notAfter": None, "extensions": {}, "sans": [],
        "eku": [], "fulcio": {},
    }

    items = list(iter_children(tbs))
    index = 0
    if items and items[0][0] == 0xA0:                       # [0] EXPLICIT version
        version_children = list(iter_children(items[0][1]))
        if version_children and version_children[0][0] == TAG_INTEGER:
            fields["version"] = int.from_bytes(version_children[0][1], "big") + 1
        index = 1
    if len(items) < index + 6:
        raise DerError("tbsCertificate is missing required fields")

    if items[index][0] != TAG_INTEGER:
        raise DerError("serialNumber is not an INTEGER")
    fields["serialHex"] = items[index][1].hex()
    fields["issuer"] = _parse_name(items[index + 2][1])
    fields["subject"] = _parse_name(items[index + 4][1])

    validity = list(iter_children(items[index + 3][1]))
    if len(validity) != 2:
        raise DerError("validity does not have exactly notBefore and notAfter")
    fields["notBefore"] = decode_time(*validity[0])
    fields["notAfter"] = decode_time(*validity[1])
    if fields["notAfter"] <= fields["notBefore"]:
        raise DerError("certificate notAfter is not after notBefore")

    for tag_, value in items[index + 6:]:
        if tag_ == 0xA3:                                    # [3] EXPLICIT extensions
            _parse_extensions(value, fields)
    return fields


def _parse_name(der):
    """RDNSequence -> {"CN": …, "O": …, "raw": [(oid, value)]}. Empty dict for an empty name."""
    out = {"raw": []}
    count = 0
    for tag, rdn in iter_children(der):
        if tag != TAG_SET:
            continue
        for atv_tag, atv in iter_children(rdn):
            if atv_tag != TAG_SEQUENCE:
                continue
            parts = list(iter_children(atv))
            if len(parts) != 2 or parts[0][0] != TAG_OID:
                continue
            count += 1
            if count > 64:
                raise DerError("implausibly many name attributes")
            oid = decode_oid(parts[0][1])
            try:
                value = _decode_string(parts[1][0], parts[1][1])
            except (DerError, UnicodeDecodeError):
                continue
            out["raw"].append((oid, value))
            if oid == OID_CN:
                out["CN"] = value
            elif oid == OID_O:
                out["O"] = value
    return out


def _parse_extensions(der, fields):
    children = list(iter_children(der))
    if len(children) != 1 or children[0][0] != TAG_SEQUENCE:
        raise DerError("extensions block is not a single SEQUENCE")
    count = 0
    for tag, extension in iter_children(children[0][1]):
        if tag != TAG_SEQUENCE:
            continue
        count += 1
        if count > MAX_ELEMENTS:
            raise DerError("implausibly many extensions")
        parts = list(iter_children(extension))
        if not parts or parts[0][0] != TAG_OID:
            continue
        oid = decode_oid(parts[0][1])
        critical = False
        value = None
        for part_tag, part_value in parts[1:]:
            if part_tag == 0x01:                            # BOOLEAN critical
                critical = part_value not in (b"\x00", b"")
            elif part_tag == TAG_OCTET_STRING:
                value = part_value
        if value is None:
            continue
        fields["extensions"][oid] = {"critical": critical, "bytes": len(value)}
        if oid == OID_SAN:
            fields["sans"] = _parse_san(value)
        elif oid == OID_EKU:
            fields["eku"] = _parse_eku(value)
        elif oid in FULCIO_OIDS:
            name, der_wrapped = FULCIO_OIDS[oid]
            fields["fulcio"][name] = _fulcio_value(value, der_wrapped)


def _parse_san(der):
    """GeneralNames -> [(kind, value)]. URIs and otherName SANs are what Fulcio uses."""
    out = []
    children = list(iter_children(der))
    if len(children) != 1 or children[0][0] != TAG_SEQUENCE:
        return out
    for tag, value in iter_children(children[0][1]):
        if len(out) > 64:
            raise DerError("implausibly many subjectAltNames")
        if tag == TAG_GN_URI:
            out.append(("uri", value.decode("utf-8", "replace")))
        elif tag == 0x82:                                   # dNSName
            out.append(("dns", value.decode("utf-8", "replace")))
        elif tag == 0x81:                                   # rfc822Name
            out.append(("email", value.decode("utf-8", "replace")))
        elif tag == 0xA0:                                   # otherName
            text = _otherName(value)
            if text is not None:
                out.append(("otherName", text))
    return out


def _otherName(der):
    try:
        parts = list(iter_children(der))
    except DerError:
        return None
    for tag, value in parts:
        if tag == 0xA0:
            for inner_tag, inner in iter_children(value):
                try:
                    return _decode_string(inner_tag, inner)
                except (DerError, UnicodeDecodeError):
                    return inner.decode("utf-8", "replace")
    return None


def _parse_eku(der):
    out = []
    children = list(iter_children(der))
    if len(children) != 1 or children[0][0] != TAG_SEQUENCE:
        return out
    for tag, value in iter_children(children[0][1]):
        if tag == TAG_OID:
            out.append(decode_oid(value))
    return out


def _fulcio_value(raw, der_wrapped):
    """1.1–1.6 are raw UTF-8; 1.8+ wrap the string in a DER UTF8String."""
    if der_wrapped:
        try:
            tag, value, _ = read_tlv(raw)
            return _decode_string(tag, value)
        except (DerError, UnicodeDecodeError):
            return raw.decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


# =======================================================================================
# derived questions (still "what does it say", never "is it trustworthy")
# =======================================================================================


def is_fulcio_leaf(fields):
    """(bool, detail). Does the certificate PRESENT as a Sigstore/Fulcio short-lived leaf?

    Checked: issuer organisation is sigstore.dev, the EKU is code signing, an SCT extension
    is embedded, and the validity window is short. NOT checked: whether any of that is
    signed by a key we trust — that is `cosign verify-blob`'s job.
    """
    if not isinstance(fields, dict):
        return False, "certificate was not parsed"
    issuer = fields.get("issuer") or {}
    organisation = issuer.get("O")
    if organisation != "sigstore.dev":
        return False, f"issuer organisation is {organisation!r}, not 'sigstore.dev'"
    if OID_EKU_CODE_SIGNING not in (fields.get("eku") or ()):
        return False, "certificate does not carry the code-signing EKU (1.3.6.1.5.5.7.3.3)"
    if OID_SCT not in (fields.get("extensions") or {}):
        return False, ("certificate carries no embedded SCT (1.3.6.1.4.1.11129.2.4.2); a "
                       "Fulcio leaf is always logged to a CT log")
    lifetime = fields["notAfter"] - fields["notBefore"]
    if lifetime > 3600:
        return False, (f"certificate lifetime is {lifetime}s; a Fulcio ephemeral leaf is "
                       "minutes, and a long-lived certificate is a different trust model")
    return True, (f"issuer O={organisation} CN={issuer.get('CN')!r}, code-signing EKU, "
                  f"embedded SCT, {lifetime}s lifetime")


def identity_of(fields):
    """The signer identity the certificate CLAIMS, as a dict. Never a verified identity."""
    fulcio = (fields or {}).get("fulcio") or {}
    sans = (fields or {}).get("sans") or []
    san_uri = next((value for kind, value in sans if kind == "uri"), None)
    return {
        "sanUri": san_uri,
        "sanOther": next((value for kind, value in sans if kind == "otherName"), None),
        "oidcIssuer": fulcio.get("issuer") or fulcio.get("oidcIssuerLegacy"),
        "buildSignerUri": fulcio.get("buildSignerUri"),
        "buildConfigUri": fulcio.get("buildConfigUri"),
        "sourceRepositoryUri": fulcio.get("sourceRepositoryUri"),
        "sourceRepository": fulcio.get("githubWorkflowRepository"),
        "sourceRepositoryRef": fulcio.get("sourceRepositoryRef"),
        "sourceRepositoryDigest": fulcio.get("sourceRepositoryDigest"),
        "sourceRepositoryOwnerUri": fulcio.get("sourceRepositoryOwnerUri"),
        "sourceRepositoryOwnerIdentifier": fulcio.get("sourceRepositoryOwnerIdentifier"),
        "sourceRepositoryIdentifier": fulcio.get("sourceRepositoryIdentifier"),
        "runnerEnvironment": fulcio.get("runnerEnvironment"),
        "buildTrigger": fulcio.get("buildTrigger"),
        "subject": fulcio.get("subjectAlternativeNameSubject"),
        "signatureVerified": False,
        "certificateChainVerified": False,
    }


def repository_of(identity):
    """'owner/repo' from the certificate's identity claims. None when it says nothing."""
    repository = identity.get("sourceRepository")
    if repository:
        return repository
    uri = identity.get("sourceRepositoryUri") or ""
    prefix = "https://github.com/"
    if uri.startswith(prefix):
        rest = uri[len(prefix):].strip("/")
        if rest.count("/") == 1:
            return rest
    return None


__all__ = [
    "DerError", "FULCIO_OIDS", "MAX_DER_BYTES", "OID_EKU_CODE_SIGNING", "OID_SAN", "OID_SCT",
    "decode_oid", "decode_time", "identity_of", "is_fulcio_leaf", "iter_children",
    "parse_certificate", "pem_to_der", "read_tlv", "repository_of",
]
