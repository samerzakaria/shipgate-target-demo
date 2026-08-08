"""Pinned trust material, and the only place in this kit that verifies a signature.

WHY THIS FILE EXISTS. Until v4.1 the kit verified no signature at all. `parsers/_x509.py` is
a read-only ASN.1 walk with no crypto, and `parsers/rekor.py` recomputed an RFC 6962 inclusion
proof against a root hash the operator supplied — internal consistency, not inclusion in the
public log. An external audit put it plainly: a Merkle proof against an attacker-supplied root
proves nothing about Rekor, so `integratedTime` was not a trustworthy external clock and
nothing downstream of it could be either.

The old refusal was reasoned, and worth restating because it was not lazy: `parsers/rekor.py`
said "fetching or hard-coding a Rekor key would be a NEW TRUST ROOT", and declined to smuggle
one in. That was the right instinct and the wrong conclusion. A verifier with no trust root
does not thereby avoid trusting anything; it silently trusts whoever wrote the files. The fix
is not to keep having no root — it is to have ONE, name it, pin it, and say exactly what it
does and does not cover.

WHAT IS PINNED. Rekor's public key, verbatim, below. Pinning means the bytes live here, in the
artifact, under the artifact's own digest — not fetched at verification time from the log that
is being verified, which would be circular. `verify_checkpoint` will not accept a substitute:
there is no configuration key that widens the trust root, for the same reason
`GithubOidcIdentityVerifier` lets an operator PIN the issuer and never widen it.

WHAT THIS DOES NOT COVER, and must be read before anyone quotes it:

  * It does not verify Fulcio certificate chains or SCTs. That is cosign's job and this kit
    still does not do it. A verified checkpoint says an entry is in the public log; it says
    nothing about whose key signed the entry.
  * It does not make the log itself trustworthy. Sigstore's log is append-only by witness and
    gossip, neither of which this kit observes. A verified checkpoint is one signature by one
    operator of one log.
  * A pinned key goes stale. Rekor rotates, and this file is a point-in-time observation with
    its provenance recorded. `refresh_note()` describes how to re-derive it; nothing here
    fetches anything at verification time.
"""
import base64
import binascii
import hashlib
from typing import Optional, Tuple

from . import p256

#: Rekor's public key for the production log `rekor.sigstore.dev`.
#:
#: PROVENANCE. Fetched from https://rekor.sigstore.dev/api/v1/log/publicKey on 2026-08-07 over
#: TLS. Corroborated, not merely downloaded: the SHA-256 of its DER SubjectPublicKeyInfo is
#: c0d23d6a…91801d, and that is byte-identical to the `logID` recorded inside
#: `captures/cosign_keyless_bundle.json`, a bundle captured months earlier by a separate cosign
#: run. Two independent observations of the same log identity agreeing is the reason this key
#: is pinned rather than merely present.
REKOR_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
"""

#: sha256 of the PEM bytes above. Asserted by the test suite so an edit to the key is a test
#: failure rather than a silent change of trust root.
REKOR_PUBLIC_KEY_SHA256 = "dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd"

#: sha256 of the DER SPKI, which is how Rekor derives the `logID` field and the 4-byte key
#: hint in a checkpoint's signature line.
REKOR_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"

#: The origin line a production checkpoint must carry. A note signed by a different log is
#: not evidence about this one, however valid its signature.
REKOR_ORIGIN = "rekor.sigstore.dev"

CRYPTO_UNAVAILABLE = (
    "the bundled P-256 verifier failed its own known-answer vectors, so no signature can be "
    "trusted. This is a REFUSAL, never a pass: an unverifiable checkpoint is exactly the "
    "state this module exists to stop being reported as verified.")


class TrustRootError(Exception):
    """Trust material could not be loaded or a signature could not be checked."""


def _crypto():
    """Admit the verifier before using it, on the kit's own fail-first rule.

    The same discipline the gate applies to a phase collector applies here: an instrument
    proves itself against known answers in both directions before it is allowed to judge
    anything. A signature checker that silently returned True would be the single worst
    defect this product could ship, and it would look exactly like success.
    """
    result = p256.self_test()
    if not result["ok"]:
        raise TrustRootError(f"{CRYPTO_UNAVAILABLE} ({result['detail']})")
    return p256


def available() -> Tuple[bool, str]:
    """(usable, detail). Never raises, so `doctor` can report it."""
    try:
        _crypto()
    except TrustRootError as exc:
        return False, str(exc)
    try:
        key_id = derived_log_id()
    except TrustRootError as exc:
        return False, str(exc)
    if key_id != REKOR_LOG_ID:
        return False, (f"the pinned key derives log id {key_id} but the pin records "
                       f"{REKOR_LOG_ID}; the trust root is inconsistent with itself")
    if pinned_key_digest() != REKOR_PUBLIC_KEY_SHA256:
        return False, "the pinned key does not match its recorded digest"
    return True, (f"Rekor trust root pinned: log {REKOR_ORIGIN}, id {REKOR_LOG_ID[:16]}…, "
                  f"ECDSA P-256")


def pinned_key_digest() -> str:
    return hashlib.sha256(REKOR_PUBLIC_KEY_PEM).hexdigest()


def _load_key():
    """The pinned key as an (x, y) point, curve-checked by the parser."""
    _crypto()
    try:
        return p256.public_point_from_pem(REKOR_PUBLIC_KEY_PEM)
    except p256.P256Error as exc:
        raise TrustRootError(f"the pinned Rekor key is unreadable: {exc}")


def derived_log_id() -> str:
    """sha256 of the DER SPKI — the value Rekor publishes as `logID`."""
    _crypto()
    der = p256.spki_der_from_pem(REKOR_PUBLIC_KEY_PEM)
    return hashlib.sha256(der).hexdigest()


def parse_checkpoint(text: str):
    """Split a signed note into (body, origin, tree_size, root_hash_b64, signatures).

    Format is the Sigstore/transparency-dev signed note: a body of at least three lines
    (origin, size, root hash), a blank line, then one or more `— <name> <base64>` lines. The
    body INCLUDING its trailing newline is what is signed; getting that wrong produces a
    verification failure that looks like a forged note, so it is done in one place.
    """
    if not isinstance(text, str) or "\n\n" not in text:
        raise TrustRootError("checkpoint is not a signed note: no blank line separating the "
                             "body from its signatures")
    body, _, sigblock = text.partition("\n\n")
    body = body + "\n"
    lines = body.splitlines()
    if len(lines) < 3:
        raise TrustRootError(f"checkpoint body has {len(lines)} lines, expected at least 3 "
                             f"(origin, tree size, root hash)")
    # Sigstore writes the origin as "<host> - <treeID>". The host is the trust decision; the
    # tree id identifies the shard and is carried through as a fact rather than compared,
    # because Rekor shards and a hard-coded shard id would expire faster than the key.
    origin = lines[0].strip()
    try:
        tree_size = int(lines[1].strip())
    except ValueError:
        raise TrustRootError(f"checkpoint tree size {lines[1]!r} is not an integer")
    root_hash_b64 = lines[2].strip()
    signatures = []
    for line in sigblock.splitlines():
        parts = line.split()
        # The separator is an em dash; some producers emit the ASCII '-' form.
        if len(parts) >= 3 and parts[0] in ("—", "-"):
            signatures.append((parts[1], parts[2]))
    if not signatures:
        raise TrustRootError("checkpoint carries no signature line")
    return body, origin, tree_size, root_hash_b64, signatures


def verify_checkpoint(text: str, expect_origin: Optional[str] = REKOR_ORIGIN):
    """Verify a Rekor checkpoint against the PINNED key. Returns a fact dict, or raises.

    Raising rather than returning a soft failure is deliberate. Every caller of this function
    is deciding whether to award provenance, and a verifier that can express "signature not
    checked" as a value will eventually have that value read as "fine".
    """
    _crypto()
    body, origin, tree_size, root_hash_b64, signatures = parse_checkpoint(text)

    host = origin.split(" - ", 1)[0].strip()
    tree_id = origin.split(" - ", 1)[1].strip() if " - " in origin else ""
    if expect_origin and host != expect_origin:
        raise TrustRootError(f"checkpoint origin host is {host!r}, not {expect_origin!r}; a "
                             f"note signed by a different log is not evidence about this one")

    key = _load_key()
    want_hint = bytes.fromhex(REKOR_LOG_ID)[:4]
    tried = []
    for name, b64 in signatures:
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            tried.append(f"{name}: signature is not valid base64")
            continue
        if len(raw) < 5:
            tried.append(f"{name}: signature block is {len(raw)} bytes, too short to carry a "
                         f"4-byte key hint and a signature")
            continue
        hint, sig = raw[:4], raw[4:]
        if hint != want_hint:
            tried.append(f"{name}: key hint {hint.hex()} is not the pinned log's "
                         f"{want_hint.hex()}")
            continue
        if not p256.verify(key, sig, body.encode("utf-8")):
            raise TrustRootError(
                f"checkpoint signature by {name!r} carries the pinned log's key hint but does "
                f"NOT verify against the pinned key. This is a forged or corrupted note, not "
                f"a stale one.")
        try:
            root = base64.b64decode(root_hash_b64, validate=True)
        except (binascii.Error, ValueError):
            raise TrustRootError("checkpoint root hash is not valid base64")
        if len(root) != 32:
            raise TrustRootError(f"checkpoint root hash is {len(root)} bytes, expected 32")
        return {
            "origin": origin,
            "originHost": host,
            "treeId": tree_id,
            "treeSize": tree_size,
            "rootHashHex": root.hex(),
            "logId": REKOR_LOG_ID,
            "signedBy": name,
            "checkpointSignatureVerified": True,
            "trustRoot": "pinned",
            "trustRootDigest": pinned_key_digest(),
            "detail": (f"ECDSA P-256 signature over the {len(body)}-byte note body verifies "
                       f"against the pinned {origin} key"),
        }
    raise TrustRootError(
        "no signature line on this checkpoint was made by the pinned Rekor log: "
        + "; ".join(tried))


def verify_signed_entry_timestamp(set_b64: str, canonical_body: bytes):
    """Verify a Rekor SignedEntryTimestamp over the canonicalised entry.

    The SET is Rekor's own signature over the entry, which is what turns `integratedTime` from
    a number in a file into an assertion by the log. Same pinned key, same refusal on failure.
    """
    _crypto()
    try:
        sig = base64.b64decode(set_b64, validate=True)
    except (binascii.Error, ValueError):
        raise TrustRootError("signedEntryTimestamp is not valid base64")
    key = _load_key()
    if not p256.verify(key, sig, canonical_body):
        raise TrustRootError(
            "signedEntryTimestamp does not verify against the pinned Rekor key; the "
            "integratedTime in this entry is not asserted by the log")
    return {"signedEntryTimestampVerified": True, "trustRoot": "pinned",
            "trustRootDigest": pinned_key_digest()}


def refresh_note() -> str:
    """How to re-derive the pin. Deliberately NOT executable from here."""
    return "\n".join([
        "The pinned Rekor key is a point-in-time observation and Rekor rotates keys.",
        "",
        "To re-derive it:",
        "  curl -s https://rekor.sigstore.dev/api/v1/log/publicKey",
        "",
        "To corroborate rather than merely trust the download, check that the sha256 of the",
        "DER SubjectPublicKeyInfo equals the `logID` recorded in an independently captured",
        f"Rekor entry. The current pin was accepted on that basis: {REKOR_LOG_ID}",
        "",
        "Nothing in this kit fetches the key at verification time. A verifier that downloads",
        "its own trust root from the service it is verifying has no trust root.",
    ])
