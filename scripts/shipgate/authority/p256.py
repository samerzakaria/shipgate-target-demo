"""ECDSA P-256 signature VERIFICATION, stdlib only.

WHY NOT `cryptography`. The kit has one dependency rule and it is load-bearing: stdlib only,
so the whole subsystem installs anywhere, runs in an air-gapped container, and can be deleted
without breaking a package manifest. `tests/boundary/test_import_boundary.py` enforces it.
Taking a binary dependency to check one signature would trade a real property for a
convenience, and it would do it in the half of the product an adopter is most likely to be
suspicious of.

WHY THIS IS SAFE TO WRITE BY HAND. This module VERIFIES and never signs. Every input is
public — a public key, a signature, a message that is already published in a transparency log
— so there is no secret to leak through timing, and the constant-time discipline that makes
hand-rolled signing dangerous does not apply. The failure mode of a bug here is a valid
signature rejected or an invalid one accepted, and both are covered by tests: known-answer
vectors, a live Rekor checkpoint, and a differential against `cryptography` when it happens
to be installed.

WHAT IS NOT HERE. No signing, no key generation, no other curve, no point decompression. If
you need any of those, this is the wrong module and adding them here would be how it stops
being reviewable.

References: SEC1 v2 §4.1.4 (verification), FIPS 186-4 §6.4, RFC 5480 (SPKI), RFC 3279 §2.2.3
(the DER Ecdsa-Sig-Value).
"""
import hashlib

# --- curve NIST P-256 / secp256r1 / prime256v1 -----------------------------------------
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


class P256Error(ValueError):
    """Malformed key, signature or point. Never raised for a merely invalid signature."""


# --- point arithmetic in Jacobian coordinates ------------------------------------------
# Affine (x, y) -> Jacobian (X, Y, Z) with x = X/Z^2, y = Y/Z^3. Jacobian avoids a modular
# inversion per addition; one inversion at the end converts back.

def _double(pt):
    x, y, z = pt
    if not y:
        return (0, 0, 0)
    ysq = (y * y) % P
    s = (4 * x * ysq) % P
    m = (3 * x * x + A * pow(z, 4, P)) % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * ysq * ysq) % P
    nz = (2 * y * z) % P
    return (nx, ny, nz)


def _add(p1, p2):
    if not p1[2]:
        return p2
    if not p2[2]:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1sq, z2sq = pow(z1, 2, P), pow(z2, 2, P)
    u1 = (x1 * z2sq) % P
    u2 = (x2 * z1sq) % P
    s1 = (y1 * z2sq * z2) % P
    s2 = (y2 * z1sq * z1) % P
    if u1 == u2:
        return _double(p1) if s1 == s2 else (0, 0, 0)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    hsq = (h * h) % P
    hcu = (hsq * h) % P
    nx = (r * r - hcu - 2 * u1 * hsq) % P
    ny = (r * (u1 * hsq - nx) - s1 * hcu) % P
    nz = (h * z1 * z2) % P
    return (nx, ny, nz)


def _mul(k, pt):
    k %= N
    result = (0, 0, 0)
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    return result


def _to_affine(pt):
    x, y, z = pt
    if not z:
        return None
    zinv = pow(z, P - 2, P)          # Fermat inverse; P is prime
    return ((x * pow(zinv, 2, P)) % P, (y * pow(zinv, 3, P)) % P)


def _on_curve(x, y):
    return (y * y - (x * x * x + A * x + B)) % P == 0


# --- DER --------------------------------------------------------------------------------

def _der_int(buf, i):
    if i >= len(buf) or buf[i] != 0x02:
        raise P256Error(f"expected a DER INTEGER at offset {i}")
    length = buf[i + 1]
    if length & 0x80:
        raise P256Error("long-form INTEGER length is not valid in an ECDSA signature")
    start = i + 2
    end = start + length
    if end > len(buf):
        raise P256Error("DER INTEGER runs past the end of the buffer")
    return int.from_bytes(buf[start:end], "big"), end


def decode_signature(der):
    """DER `SEQUENCE { INTEGER r, INTEGER s }` -> (r, s)."""
    if not der or der[0] != 0x30:
        raise P256Error("signature is not a DER SEQUENCE")
    length = der[1]
    if length & 0x80:
        count = length & 0x7F
        body = 2 + count
        length = int.from_bytes(der[2:body], "big")
    else:
        body = 2
    if body + length > len(der):
        raise P256Error("DER SEQUENCE length exceeds the buffer")
    r, i = _der_int(der, body)
    s, _ = _der_int(der, i)
    return r, s


def public_point_from_spki(der):
    """Pull the uncompressed EC point out of a DER SubjectPublicKeyInfo.

    Scans for the 0x04 uncompressed marker followed by exactly 64 bytes at the end of the
    structure rather than walking the full ASN.1, and then CHECKS THE POINT IS ON THE CURVE —
    which is the property that actually matters and is stronger than trusting the parse.
    """
    if len(der) < 65:
        raise P256Error("SubjectPublicKeyInfo is too short to contain a P-256 point")
    tail = der[-65:]
    if tail[0] != 0x04:
        raise P256Error("public key is not an uncompressed P-256 point (no 0x04 marker)")
    x = int.from_bytes(tail[1:33], "big")
    y = int.from_bytes(tail[33:65], "big")
    if not (0 <= x < P and 0 <= y < P):
        raise P256Error("public key coordinates are out of the field")
    if not _on_curve(x, y):
        raise P256Error("public key point is not on the P-256 curve")
    return x, y


def public_point_from_pem(pem):
    """PEM `-----BEGIN PUBLIC KEY-----` -> (x, y)."""
    import base64
    text = pem.decode("ascii") if isinstance(pem, (bytes, bytearray)) else str(pem)
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.strip().startswith("-----")]
    if not lines:
        raise P256Error("PEM contains no base64 body")
    try:
        der = base64.b64decode("".join(lines), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise P256Error(f"PEM body is not valid base64: {exc}")
    return public_point_from_spki(der)


def spki_der_from_pem(pem):
    import base64
    text = pem.decode("ascii") if isinstance(pem, (bytes, bytearray)) else str(pem)
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.strip().startswith("-----")]
    return base64.b64decode("".join(lines), validate=True)


# --- verification -------------------------------------------------------------------------

def verify(public_point, signature_der, message, digestmod=hashlib.sha256):
    """True if `signature_der` is a valid ECDSA signature over `message`. SEC1 §4.1.4.

    Returns False for an invalid signature. Raises `P256Error` only when the inputs are
    malformed — the distinction matters, because a caller must be able to tell "this is not a
    signature" from "this signature is wrong".
    """
    qx, qy = public_point
    if not _on_curve(qx, qy):
        raise P256Error("public key point is not on the curve")
    r, s = decode_signature(signature_der)
    if not (1 <= r < N and 1 <= s < N):
        return False
    digest = digestmod(message).digest()
    # e is the leftmost min(bitlen(N), hashlen) bits. For P-256 with SHA-256 they are equal,
    # so no truncation happens; the shift is written out so a different hash stays correct.
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - N.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, N - 2, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    point = _add(_mul(u1, (GX, GY, 1)), _mul(u2, (qx, qy, 1)))
    affine = _to_affine(point)
    if affine is None:
        return False
    return affine[0] % N == r


def self_test():
    """Known-answer vectors. Runs with no network and no fixtures.

    The negative vectors matter more than the positive one: an implementation that returns
    True unconditionally passes every positive test ever written.
    """
    # RFC 6979 A.2.5 P-256 / SHA-256, message "sample".
    qx = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    qy = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

    def der(rv, sv):
        def i(v):
            b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return b"\x02" + bytes([len(b)]) + b
        body = i(rv) + i(sv)
        return b"\x30" + bytes([len(body)]) + body

    failures = []
    if not verify((qx, qy), der(r, s), b"sample"):
        failures.append("the RFC 6979 A.2.5 known-good vector did not verify")
    if verify((qx, qy), der(r, s), b"sampl3"):
        failures.append("a signature verified against the WRONG message")
    if verify((qx, qy), der((r + 1) % N, s), b"sample"):
        failures.append("a signature with a tampered r verified")
    if verify((qx, qy), der(r, (s + 1) % N), b"sample"):
        failures.append("a signature with a tampered s verified")
    if verify((qx, qy), der(0, s), b"sample"):
        failures.append("r = 0 was accepted, violating the SEC1 range check")
    if verify((qx, qy), der(r, N), b"sample"):
        failures.append("s = n was accepted, violating the SEC1 range check")
    try:
        verify((qx, qy + 1), der(r, s), b"sample")
        failures.append("a public key off the curve was accepted")
    except P256Error:
        pass
    return {"ok": not failures, "failures": failures,
            "detail": "P-256 verifier passed its known-answer vectors in both directions"
                      if not failures else "; ".join(failures)}
