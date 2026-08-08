"""cosign output parsing: `version --json`, the sign-blob bundle, and `verify-blob`.

Scope note. This module NEVER verifies a signature itself. Signature verification is
`cosign verify-blob`'s job; re-implementing ECDSA here would be the "cryptographic
infrastructure beyond scope" the release forbids, and hand-rolled crypto in a trust gate is
worse than no crypto. What this module does instead is:

  * decide whether cosign's own verdict is one of the two texts we have actually captured,
    and treat every other text as unknown — never as success;
  * check the bundle's INTERNAL consistency, which is cheap, dependency-free, and catches
    tampering without any key material:
        messageSignature.signature  ==  tlog body spec.signature.content
        messageSignature.messageDigest == tlog body spec.data.hash.value
        verificationMaterial.publicKey.hint == b64(sha256(SPKI DER of the signing key))
        the embedded Merkle inclusion proof verifies against its own checkpoint root
    Flipping a byte anywhere in the signature therefore fails: change it in one place and the
    cross-check breaks; change it in both and the transparency-log leaf hash moves, so the
    inclusion proof breaks.
  * bind the bundle to a decision digest, which is the only thing that makes the signature
    evidence ABOUT this decision rather than about some blob.
"""
import base64
import hashlib

from ...models import reasons as R
from .. import shapes
from . import _common as C
from . import _x509
from . import rekor as _rekor

SHAPE_VERSION = "cosign.version.v1"
SHAPE_BUNDLE_KEYED = "cosign.bundle.keyed.v0_3"
#: The SECOND capture of that same serialisation, from cosign v3.1.3 (captures/normalized/
#: bundle_v03.json). The keyed sigstore-bundle-v0.3 envelope was NOT first seen here — the
#: original cosign_signblob_bundle.json is already mediaType v0.3+json with
#: verificationMaterial.tlogEntries and an embedded inclusion proof. Two near-identical ids for
#: one serialisation is a trap, so it is spelled out here and asserted in selfcheck.
SHAPE_BUNDLE_KEYED_V03 = "cosign.bundle.v0_3.keyed"
#: Every registered capture of the keyed v0.3 envelope, canonical id first. A parser needs ONE
#: of them validated; redundancy, not two contracts.
KEYED_V03_SHAPES = (SHAPE_BUNDLE_KEYED, SHAPE_BUNDLE_KEYED_V03)
#: The sigstore bundle v0.3 KEYLESS variant (verificationMaterial.certificate). Still has no
#: real capture — see SHAPE_BUNDLE_KEYLESS_LEGACY for the shape that does. bundle_v03.json did
#: NOT unblock it: that capture is KEYED (publicKey.hint), and keyless signing needs an OIDC
#: token that this sandbox cannot obtain without a human at a browser
#: (captures/normalized/keyless_attempt.txt).
SHAPE_BUNDLE_KEYLESS = "cosign.bundle.keyless.v0_3"
#: The LEGACY cosign bundle: {base64Signature, cert, rekorBundle}. This is what the real
#: keyless capture turned out to be — a different serialisation from the v0.3 bundle, not a
#: keyless flavour of it.
SHAPE_BUNDLE_KEYLESS_LEGACY = "cosign.bundle.keyless.legacy.v1"
SHAPE_VERIFY_OK = "cosign.verifyblob.ok.v1"
SHAPE_VERIFY_FAIL = "cosign.verifyblob.fail.v1"
#: The v3.1.3 re-captures of the two verify-blob texts. BYTE-IDENTICAL to the v3.1.2 ones —
#: the text did not drift across the version bump, which is the finding — so these add VERSION
#: coverage, not shape coverage.
SHAPE_VERIFY_OK_V03 = "cosign.verifyblob.v03.ok.v1"
SHAPE_VERIFY_FAIL_V03 = "cosign.verifyblob.v03.fail.v1"
VERIFY_OK_SHAPES = (SHAPE_VERIFY_OK, SHAPE_VERIFY_OK_V03)
VERIFY_FAIL_SHAPES = (SHAPE_VERIFY_FAIL, SHAPE_VERIFY_FAIL_V03)

#: Two producing versions are recorded rather than one averaged claim. See SHAPES.json
#: `versionTiers`: v3.1.2 produced the original corpus, v3.1.3 the 2026-08-06 v0.3 round.
VERSION_GATE = C.VersionGate("cosign", minimum=(3, 0, 0), below=(4, 0, 0),
                             validated="v3.1.2 and v3.1.3")

#: The only bundle media type present in a real capture.
SUPPORTED_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

# --- the exact verify-blob texts, transcribed from the captures ------------------------
# `selftest`/`selfcheck` asserts these are byte-identical to captures/normalized/, so they
# can never drift from what the tool really printed.
VERIFY_OK_TEXT = "Verified OK"
VERIFY_FAIL_TAIL = ("failed to verify signature: could not verify message: invalid signature "
                    "when validating ASN.1 encoded signature")
VERIFY_FAIL_LINE1 = "Error: " + VERIFY_FAIL_TAIL
VERIFY_FAIL_LINE2 = "error during command execution: " + VERIFY_FAIL_TAIL


# =======================================================================================
# cosign version --json
# =======================================================================================


def parse_version(raw, registry=None):
    """`cosign version --json` -> ParseResult(data={"version", "tuple", "platform", ...})."""
    reg = registry or shapes.registry()
    res, doc = C.load_json(raw, SHAPE_VERSION)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_VERSION, reg)
    if not good:
        return C.fail(SHAPE_VERSION, code, detail)
    version = doc["gitVersion"]
    supported, code, detail = VERSION_GATE.check(version)
    if not supported:
        return C.fail(SHAPE_VERSION, code, detail)
    if doc.get("gitTreeState") != "clean":
        return C.fail(SHAPE_VERSION, R.AUT_TOOL_VERSION_UNSUPPORTED,
                      f"cosign reports gitTreeState={doc.get('gitTreeState')!r}; refusing to "
                      "trust output from a locally modified build")
    return C.ok(SHAPE_VERSION, {
        "tool": "cosign", "version": version, "tuple": C.parse_semver(version),
        "commit": doc["gitCommit"], "platform": doc["platform"],
        "buildDate": doc["buildDate"], "goVersion": doc["goVersion"],
    })


# =======================================================================================
# the sign-blob bundle
# =======================================================================================


def _is_keyless(material):
    return bool(material.get("certificate") or material.get("x509CertificateChain"))


def _is_legacy_bundle(doc):
    """The legacy cosign bundle has no mediaType at all — it is a flat triple."""
    return ("base64Signature" in doc and "cert" in doc and "rekorBundle" in doc
            and "mediaType" not in doc)


def parse_bundle(raw, cosign_version=None, registry=None):
    """Parse a `cosign sign-blob --bundle` document, in whichever serialisation it arrived.

    Three shapes are recognised, and only two of them can succeed:

      * sigstore bundle v0.3, KEYED (`verificationMaterial.publicKey`)  -> parsed here
      * the LEGACY cosign bundle (`{base64Signature, cert, rekorBundle}`), which is what a
        real keyless capture turned out to be                            -> parsed keylessly
      * sigstore bundle v0.3, KEYLESS (`verificationMaterial.certificate`) -> still BLOCKED;
        no capture of THAT serialisation exists, and validating its schema against a
        differently-shaped file would be exactly the fabrication this kit refuses.
    """
    reg = registry or shapes.registry()
    if cosign_version is not None:
        supported, code, detail = VERSION_GATE.check(cosign_version)
        if not supported:
            return C.fail(SHAPE_BUNDLE_KEYED, code, detail)

    res, doc = C.load_json(raw, SHAPE_BUNDLE_KEYED)
    if res is not None:
        return res
    if not isinstance(doc, dict):
        return C.unknown(SHAPE_BUNDLE_KEYED, "bundle is not a JSON object")

    if _is_legacy_bundle(doc):
        return parse_keyless_bundle(doc, registry=reg)

    media = doc.get("mediaType")
    if media != SUPPORTED_MEDIA_TYPE:
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         f"unsupported bundle mediaType {media!r}; only "
                         f"{SUPPORTED_MEDIA_TYPE!r} has been captured and validated")

    material = doc.get("verificationMaterial")
    if not isinstance(material, dict):
        return C.unknown(SHAPE_BUNDLE_KEYED, "bundle has no verificationMaterial object")

    if _is_keyless(material):
        # The branch exists; the shape does not. Fail closed with the reason spelled out.
        good, code, detail = reg.require_validated(SHAPE_BUNDLE_KEYLESS)
        if not good:
            return C.fail(SHAPE_BUNDLE_KEYLESS, code,
                          "this is a KEYLESS bundle (Fulcio certificate material present). "
                          + detail)
        return C.unknown(SHAPE_BUNDLE_KEYLESS,
                         "keyless bundle parsing is registered but not implemented beyond "
                         "shape recognition")

    good, code, detail, _chosen = shapes.validate_shape_any(doc, KEYED_V03_SHAPES, reg)
    if not good:
        return C.fail(SHAPE_BUNDLE_KEYED, code, detail)

    entries = material["tlogEntries"]
    if len(entries) != 1:
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         f"{len(entries)} tlog entries; only the single-entry shape has been "
                         "captured")
    entry = entries[0]

    sig_res, signature = C.b64decode_strict(
        doc["messageSignature"]["signature"], "messageSignature.signature", SHAPE_BUNDLE_KEYED)
    if sig_res is not None:
        return sig_res
    well_formed, why = C.is_der_ecdsa_signature(signature)
    if not well_formed:
        return C.fail(SHAPE_BUNDLE_KEYED, R.AUT_SIGNATURE_INVALID,
                      f"messageSignature.signature is not a well-formed ECDSA signature: {why}")

    dig_res, digest = C.b64decode_strict(
        doc["messageSignature"]["messageDigest"]["digest"],
        "messageSignature.messageDigest.digest", SHAPE_BUNDLE_KEYED)
    if dig_res is not None:
        return dig_res
    if len(digest) != 32:
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         f"messageDigest is {len(digest)} bytes; SHA2_256 must be 32")
    digest_hex = digest.hex()

    body_res, body = C.b64decode_strict(
        entry["canonicalizedBody"], "tlogEntries[0].canonicalizedBody", SHAPE_BUNDLE_KEYED)
    if body_res is not None:
        return body_res
    body_doc_res, body_doc = C.load_json(body, SHAPE_BUNDLE_KEYED)
    if body_doc_res is not None:
        return body_doc_res
    envelope_bad = _check_body_envelope(body_doc, SHAPE_BUNDLE_KEYED)
    if envelope_bad is not None:
        return envelope_bad
    spec = body_doc["spec"]
    if not isinstance(spec, dict):
        return C.unknown(SHAPE_BUNDLE_KEYED, "tlog body spec is not an object")

    # --- cross-check 1: the logged hash IS the signed message digest -------------------
    try:
        logged_hash = spec["data"]["hash"]
        logged_sig = spec["signature"]["content"]
        logged_key = spec["signature"]["publicKey"]["content"]
    except (KeyError, TypeError):
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         "tlog body is missing spec.data.hash / spec.signature fields")
    if logged_hash.get("algorithm") != "sha256" or logged_hash.get("value") != digest_hex:
        return C.fail(SHAPE_BUNDLE_KEYED, R.AUT_BINDING_MISMATCH,
                      "the transparency-log entry does not cover this bundle's message digest "
                      f"(bundle={digest_hex[:16]}… log={str(logged_hash.get('value'))[:16]}…)")

    # --- cross-check 2: the logged signature IS this bundle's signature ----------------
    if logged_sig != doc["messageSignature"]["signature"]:
        return C.fail(SHAPE_BUNDLE_KEYED, R.AUT_SIGNATURE_INVALID,
                      "the signature in the transparency-log entry differs from the bundle's "
                      "messageSignature; the bundle has been altered after logging")

    # --- cross-check 3: the key hint IS this signing key -------------------------------
    key_res, pem = C.b64decode_strict(logged_key, "spec.signature.publicKey.content",
                                      SHAPE_BUNDLE_KEYED)
    if key_res is not None:
        return key_res
    spki = _spki_from_pem(pem)
    if spki is None:
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         "logged public key is not a PEM 'PUBLIC KEY' block")
    hint = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    if hint != material["publicKey"]["hint"]:
        return C.fail(SHAPE_BUNDLE_KEYED, R.AUT_SIGNATURE_INVALID,
                      "verificationMaterial.publicKey.hint does not identify the key that "
                      "signed the logged entry")

    # --- cross-check 4: the inclusion proof verifies -----------------------------------
    proof = entry["inclusionProof"]
    leaf = C.sha256(b"\x00", body)
    proof_res = _rekor.verify_inclusion_proof(
        leaf_hash=leaf,
        log_index=int(proof["logIndex"]),
        tree_size=int(proof["treeSize"]),
        hashes=proof["hashes"],
        root_hash=proof["rootHash"],
        encoding="base64",
        shape_id=SHAPE_BUNDLE_KEYED,
    )
    if not proof_res.ok:
        return proof_res

    cp_res = _rekor.parse_checkpoint(proof["checkpoint"]["envelope"], SHAPE_BUNDLE_KEYED)
    if not cp_res.ok:
        return cp_res
    checkpoint = cp_res.data
    if checkpoint["rootHashB64"] != proof["rootHash"] or \
            checkpoint["treeSize"] != int(proof["treeSize"]):
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         "checkpoint root/size does not match the inclusion proof it is "
                         "attached to")
    log_id_res, log_id = C.b64decode_strict(entry["logId"]["keyId"], "logId.keyId",
                                            SHAPE_BUNDLE_KEYED)
    if log_id_res is not None:
        return log_id_res
    if checkpoint["keyHintHex"] != log_id.hex()[:8]:
        return C.unknown(SHAPE_BUNDLE_KEYED,
                         f"checkpoint signature key hint {checkpoint['keyHintHex']} does not "
                         f"match logId {log_id.hex()[:8]}")

    # --- shape-only: the RFC3161 timestamp token ---------------------------------------
    timestamps = []
    tsvd = material.get("timestampVerificationData") or {}
    for i, ts in enumerate(tsvd.get("rfc3161Timestamps", ())):
        ts_res, token = C.b64decode_strict(ts["signedTimestamp"],
                                           f"rfc3161Timestamps[{i}]", SHAPE_BUNDLE_KEYED)
        if ts_res is not None:
            return ts_res
        good_der, why = C.is_der_sequence(token)
        if not good_der:
            return C.unknown(SHAPE_BUNDLE_KEYED,
                             f"rfc3161Timestamps[{i}] is not a DER structure: {why}")
        timestamps.append({"bytes": len(token)})

    try:
        integrated_time = int(entry["integratedTime"])
    except (TypeError, ValueError):
        return C.unknown(SHAPE_BUNDLE_KEYED, "integratedTime is not an integer string")

    return C.ok(SHAPE_BUNDLE_KEYED, {
        "mediaType": media,
        "keyless": False,
        "messageDigestHex": digest_hex,
        "signatureB64": doc["messageSignature"]["signature"],
        "publicKeyHint": material["publicKey"]["hint"],
        "logIndex": int(entry["logIndex"]),
        "logIdHex": log_id.hex(),
        "integratedTime": integrated_time,
        "kind": "hashedrekord",
        "checkpoint": checkpoint,
        "inclusionProofVerified": True,
        "inclusionProofPresent": True,
        # For the cross-source check against the Rekor REST entry. The body is the Merkle
        # LEAF, so "same body" is the strongest possible statement that two documents describe
        # one log entry — much stronger than matching indices, which are just integers.
        "bodyB64": entry["canonicalizedBody"],
        "leafHashHex": leaf.hex(),
        "proofLogIndex": int(proof["logIndex"]),
        "shardOffset": int(entry["logIndex"]) - int(proof["logIndex"]),
        "treeSize": int(proof["treeSize"]),
        "rootHashHex": checkpoint["rootHashHex"],
        "rfc3161Timestamps": timestamps,
        "hasInclusionPromise": bool(entry.get("inclusionPromise")),
    })


def check_tlog_agreement(bundle_data, entry_data, shape_id=SHAPE_BUNDLE_KEYED):
    """Do the bundle's embedded tlog entry and a Rekor REST entry describe the SAME entry?

    Two independent sources — one written by cosign at signing time, one fetched from the log
    afterwards. A DISAGREEMENT is a refusal, never a merge and never a "take the newer one".
    Merging two contradictory records is how you end up attesting a signature that was never
    logged: whichever source is lying, the correct output is that they contradict.

    What is NOT required to match, and why: `treeSize` and `rootHash`. The REST entry is fetched
    later, by which time the log has appended more leaves, so the two proofs are against
    different — both valid — tree heads. On this corpus the bundle proves against 2232883522
    and the REST entry against 2232891025, 7503 leaves later. Requiring those to be equal would
    reject every honest re-fetch. What MUST match is the entry's identity: the leaf body, the
    log, the index, and the time the log says it integrated it.
    """
    if not isinstance(bundle_data, dict) or "logIndex" not in bundle_data:
        return C.unknown(shape_id, "cannot cross-check: no bundle was parsed")
    if not isinstance(entry_data, dict) or "logIndex" not in entry_data:
        return C.unknown(shape_id, "cannot cross-check: no Rekor REST entry was parsed")

    disagreements = []
    for label, left, right in (
            ("logIndex", bundle_data.get("logIndex"), entry_data.get("logIndex")),
            ("integratedTime", bundle_data.get("integratedTime"),
             entry_data.get("integratedTime")),
            ("logId", bundle_data.get("logIdHex"), entry_data.get("logIdHex")),
            ("leafHash", bundle_data.get("leafHashHex"), entry_data.get("leafHashHex")),
            ("loggedBody", bundle_data.get("bodyB64"), entry_data.get("bodyB64")),
            ("shardOffset", bundle_data.get("shardOffset"), entry_data.get("shardOffset"))):
        if left is None or right is None:
            continue
        if left != right:
            disagreements.append({"field": label, "bundle": _short(left), "rekor": _short(right)})

    if disagreements:
        fields = ", ".join(d["field"] for d in disagreements)
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"the bundle's transparency-log entry and the Rekor REST entry disagree "
                      f"on: {fields}. These are two claims about ONE log entry; when they "
                      "contradict, the contradiction IS the finding — this kit does not pick a "
                      "winner and does not merge them.",
                      data={"disagreements": disagreements})
    return C.ok(shape_id, {
        "logIndex": bundle_data["logIndex"],
        "integratedTime": bundle_data.get("integratedTime"),
        "sameLoggedBody": bundle_data.get("bodyB64") == entry_data.get("bodyB64"),
        "bundleTreeSize": bundle_data.get("treeSize"),
        "rekorTreeSize": entry_data.get("treeSize"),
        "note": "the bundle's tlog entry and the REST entry describe the same log entry; their "
                "inclusion proofs are against different (both valid) tree heads because the "
                "REST entry was fetched after more leaves were appended",
    })


def _short(value):
    text = str(value)
    return text if len(text) <= 48 else text[:45] + "…"


# =======================================================================================
# the KEYLESS (legacy) bundle: {base64Signature, cert, rekorBundle}
# =======================================================================================


def parse_keyless_bundle(raw, cosign_version=None, registry=None):
    """Parse the legacy cosign bundle produced by a keyless `sign-blob --bundle`.

    This is the shape that carries an IDENTITY: `cert` is a Fulcio ephemeral leaf whose
    extensions name the workflow, repository, commit and runner that signed. The parser
    reads that identity out of the DER and cross-checks everything that can be checked
    without a trust root:

        base64Signature   == rekorBundle.Payload.body -> spec.signature.content
        cert              == rekorBundle.Payload.body -> spec.signature.publicKey.content
        integratedTime    falls INSIDE the certificate's validity window
        the certificate presents as a Fulcio leaf (issuer, code-signing EKU, SCT, lifetime)

    That last check is worth stating: a Fulcio leaf lives about ten minutes, so "the log
    entry was made while the certificate was valid" is a real constraint, and it ties the
    transparency-log record to this specific short-lived identity.

    What is NOT checked: the certificate's signature, its chain to the Sigstore root, its
    SCT, and the ECDSA signature itself. Those need crypto and trust roots that are out of
    this release's bounded scope — they are `cosign verify-blob`'s job, and this kit refuses
    to accept a bundle unless cosign's own verdict is also supplied (see the verifier).

    IMPORTANT: this bundle carries NO inclusion proof — the legacy `rekorBundle` has only a
    SignedEntryTimestamp. `inclusionProofPresent` is False and the REST entry is required for
    a proof, exactly as with `rekor-cli`.
    """
    reg = registry or shapes.registry()
    if cosign_version is not None:
        supported, code, detail = VERSION_GATE.check(cosign_version)
        if not supported:
            return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, code, detail)

    if isinstance(raw, dict):
        doc = raw
    else:
        res, doc = C.load_json(raw, SHAPE_BUNDLE_KEYLESS_LEGACY)
        if res is not None:
            return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_BUNDLE_KEYLESS_LEGACY, reg)
    if not good:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, code, detail)

    # --- the certificate ---------------------------------------------------------------
    cert_res, pem = C.b64decode_strict(doc["cert"], "cert", SHAPE_BUNDLE_KEYLESS_LEGACY)
    if cert_res is not None:
        return cert_res
    der, err = _x509.pem_to_der(pem)
    if der is None:
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY, f"cert: {err}")
    fields, err = _x509.parse_certificate(der)
    if fields is None:
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY, f"cert: {err}")
    fulcio, why = _x509.is_fulcio_leaf(fields)
    if not fulcio:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_IDENTITY_NOT_PERMITTED,
                      f"the bundle's certificate is not a Sigstore/Fulcio leaf: {why}")
    identity = _x509.identity_of(fields)
    if identity.get("oidcIssuer") != _FULCIO_GITHUB_ISSUER:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_IDENTITY_NOT_PERMITTED,
                      f"certificate OIDC issuer is {identity.get('oidcIssuer')!r}; this kit "
                      f"only knows {_FULCIO_GITHUB_ISSUER!r}")
    if not identity.get("sanUri"):
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY,
                         "certificate carries no URI subjectAltName; a GitHub Actions Fulcio "
                         "leaf always names the workflow there")
    if identity["sanUri"] != identity.get("buildSignerUri"):
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_BINDING_MISMATCH,
                      f"certificate SAN {identity['sanUri']!r} disagrees with its own Build "
                      f"Signer URI extension {identity.get('buildSignerUri')!r}")

    # --- the signature -----------------------------------------------------------------
    sig_res, signature = C.b64decode_strict(doc["base64Signature"], "base64Signature",
                                            SHAPE_BUNDLE_KEYLESS_LEGACY)
    if sig_res is not None:
        return sig_res
    well_formed, why = C.is_der_ecdsa_signature(signature)
    if not well_formed:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_SIGNATURE_INVALID,
                      f"base64Signature is not a well-formed ECDSA signature: {why}")

    # --- the rekor bundle ---------------------------------------------------------------
    payload = doc["rekorBundle"]["Payload"]
    body_res, body = C.b64decode_strict(payload["body"], "rekorBundle.Payload.body",
                                        SHAPE_BUNDLE_KEYLESS_LEGACY)
    if body_res is not None:
        return body_res
    body_doc_res, body_doc = C.load_json(body, SHAPE_BUNDLE_KEYLESS_LEGACY)
    if body_doc_res is not None:
        return body_doc_res
    envelope_bad = _check_body_envelope(body_doc, SHAPE_BUNDLE_KEYLESS_LEGACY)
    if envelope_bad is not None:
        return envelope_bad
    try:
        logged_hash = body_doc["spec"]["data"]["hash"]
        logged_sig = body_doc["spec"]["signature"]["content"]
        logged_key = body_doc["spec"]["signature"]["publicKey"]["content"]
    except (KeyError, TypeError):
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY,
                         "tlog body is missing spec.data.hash / spec.signature fields")

    if logged_sig != doc["base64Signature"]:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_SIGNATURE_INVALID,
                      "the signature in the transparency-log entry differs from the bundle's "
                      "base64Signature; the bundle has been altered after logging")
    if logged_key != doc["cert"]:
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_SIGNATURE_INVALID,
                      "the certificate in the transparency-log entry differs from the "
                      "bundle's cert; the identity has been swapped after logging")
    if logged_hash.get("algorithm") != "sha256" or not C.hex64(logged_hash.get("value", "")):
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY,
                         f"logged data hash {logged_hash!r} is not a sha256 hex digest")

    set_res, set_raw = C.b64decode_strict(doc["rekorBundle"]["SignedEntryTimestamp"],
                                          "rekorBundle.SignedEntryTimestamp",
                                          SHAPE_BUNDLE_KEYLESS_LEGACY)
    if set_res is not None:
        return set_res
    good_der, why = C.is_der_ecdsa_signature(set_raw)
    if not good_der:
        return C.unknown(SHAPE_BUNDLE_KEYLESS_LEGACY,
                         f"SignedEntryTimestamp is not a DER signature: {why}")

    integrated_time = payload["integratedTime"]
    if not (fields["notBefore"] <= integrated_time <= fields["notAfter"]):
        return C.fail(SHAPE_BUNDLE_KEYLESS_LEGACY, R.AUT_BINDING_MISMATCH,
                      f"the log entry was integrated at {integrated_time}, outside the "
                      f"certificate's validity window [{fields['notBefore']}, "
                      f"{fields['notAfter']}]; the signature and the identity are not from "
                      "the same event")

    return C.ok(SHAPE_BUNDLE_KEYLESS_LEGACY, {
        "serialisation": "cosign-legacy-bundle",
        "keyless": True,
        "messageDigestHex": logged_hash["value"],
        "signatureB64": doc["base64Signature"],
        "logIndex": payload["logIndex"],
        "logIdHex": payload["logID"],
        "integratedTime": integrated_time,
        "kind": "hashedrekord",
        "identity": identity,
        "certificate": {
            "serialHex": fields["serialHex"],
            "issuerO": fields["issuer"].get("O"),
            "issuerCN": fields["issuer"].get("CN"),
            "notBefore": fields["notBefore"],
            "notAfter": fields["notAfter"],
            "lifetimeSeconds": fields["notAfter"] - fields["notBefore"],
            "eku": list(fields["eku"]),
            "hasEmbeddedSct": _x509.OID_SCT in fields["extensions"],
            "signatureVerified": False,
            "chainVerified": False,
            "note": "certificate CONTENT parsed; its signature, chain and SCT are NOT "
                    "verified here — that is cosign verify-blob's job",
        },
        "inclusionProofPresent": False,
        "inclusionProofVerified": False,
        "proofNote": "the legacy rekorBundle carries only a SignedEntryTimestamp, never an "
                     "inclusion proof; fetch the REST entry to prove inclusion",
    })


#: The only OIDC issuer this kit knows, duplicated from parsers.oidc to keep the modules
#: independent (cosign must not need the oidc module to read a certificate).
_FULCIO_GITHUB_ISSUER = "https://token.actions.githubusercontent.com"

#: The only hashedrekord body version present in a real capture.
_BODY_API_VERSION = "0.0.1"
_BODY_KEYS = frozenset({"apiVersion", "kind", "spec"})


def _check_body_envelope(body_doc, shape_id):
    """Strict check on a decoded Rekor entry body. None when it is the captured envelope.

    This exists because of a mutation that got through: flipping one base64 byte turned
    `"apiVersion"` into `"alVersion"`, and every cross-check still passed because nothing
    looked at that key. In the KEYED bundle the inclusion proof would have caught it — the
    body is the Merkle leaf, so any byte change moves the root. The LEGACY keyless bundle has
    NO inclusion proof, so nothing binds the body bytes at all and the envelope has to be
    checked directly. It is a small illustration of why the REST entry (which does carry the
    proof) is required for anything that needs the body to be trustworthy.
    """
    if not isinstance(body_doc, dict):
        return C.unknown(shape_id, "tlog body is not a JSON object")
    unknown_keys = sorted(set(body_doc) - _BODY_KEYS)
    if unknown_keys:
        return C.unknown(shape_id, f"tlog body has unexpected keys {unknown_keys}; the "
                                   f"captured envelope is exactly {sorted(_BODY_KEYS)}")
    missing = sorted(_BODY_KEYS - set(body_doc))
    if missing:
        return C.unknown(shape_id, f"tlog body is missing {missing}")
    if body_doc["apiVersion"] != _BODY_API_VERSION:
        return C.unknown(shape_id,
                         f"tlog body apiVersion {body_doc['apiVersion']!r} is not the "
                         f"captured {_BODY_API_VERSION!r}")
    if body_doc["kind"] != "hashedrekord":
        return C.unknown(shape_id,
                         f"tlog body kind {body_doc['kind']!r} is not the captured "
                         "'hashedrekord'")
    return None


def check_certificate_identity(bundle_data, expected_repository=None, claims=None,
                               shape_id=SHAPE_BUNDLE_KEYLESS_LEGACY):
    """Cross-check the certificate's claimed identity against the decision subject and,
    when supplied, the OIDC claim set.

    This check is STRICT and stays strict. On the shipped capture it FAILS, and that failure
    is correct: the capture's JSON was sanitised to `OWNER/REPO`, but the repository name is
    also inside the certificate's signed DER where no sanitiser could reach it. A parser that
    passed anyway would be a parser that does not really compare. See SHAPES.json
    (`bindingValidated: false`) — the capture proves SHAPE conformance, not binding.

    Returns a ParseResult. `.data` on failure carries the field-by-field comparison, because
    "which fields agree" is much more useful than "it did not match".
    """
    identity = (bundle_data or {}).get("identity")
    if not isinstance(identity, dict):
        return C.unknown(shape_id, "cannot check identity: no certificate identity was parsed")

    cert_repository = _x509.repository_of(identity)
    agreements, disagreements = [], []

    def compare(label, cert_value, other_value):
        if other_value is None or cert_value is None:
            return
        (agreements if str(cert_value) == str(other_value) else disagreements).append(
            {"field": label, "certificate": cert_value, "claimed": other_value})

    if isinstance(claims, dict):
        compare("repository", cert_repository, claims.get("repository"))
        compare("repositoryOwnerId", identity.get("sourceRepositoryOwnerIdentifier"),
                claims.get("repository_owner_id"))
        compare("commitSha", identity.get("sourceRepositoryDigest"), claims.get("sha"))
        compare("ref", identity.get("sourceRepositoryRef"), claims.get("ref"))
        compare("runnerEnvironment", identity.get("runnerEnvironment"),
                claims.get("runner_environment"))
        compare("eventName", identity.get("buildTrigger"), claims.get("event_name"))
        compare("oidcIssuer", identity.get("oidcIssuer"), claims.get("iss"))
        compare("subject", identity.get("subject"), claims.get("sub"))
        cert_workflow = (identity.get("buildSignerUri") or "").replace(
            "https://github.com/", "", 1)
        compare("jobWorkflowRef", cert_workflow or None, claims.get("job_workflow_ref"))

    if expected_repository is not None:
        compare("subjectRepository", cert_repository, expected_repository)

    comparison = {"agreements": agreements, "disagreements": disagreements,
                  "certificateRepository": cert_repository}
    if disagreements:
        fields = ", ".join(d["field"] for d in disagreements)
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"the certificate's identity disagrees with what was claimed on: "
                      f"{fields}. The certificate says repository "
                      f"{cert_repository!r}. A certificate is signed DER — when it disagrees "
                      "with the surrounding JSON, the certificate is the one telling the "
                      "truth.", data=comparison)
    if not agreements:
        return C.unknown(shape_id,
                         "nothing was supplied to compare the certificate identity against")
    return C.ok(shape_id, dict(comparison, identity=identity))


def _spki_from_pem(pem):
    """Extract the DER SubjectPublicKeyInfo from a PEM 'PUBLIC KEY' block. None if absent."""
    try:
        text = pem.decode("ascii")
    except (UnicodeDecodeError, AttributeError):
        return None
    begin, end = "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
    if begin not in text or end not in text:
        return None
    body = text.split(begin, 1)[1].split(end, 1)[0]
    try:
        return base64.b64decode("".join(body.split()), validate=True)
    except (ValueError, TypeError):
        return None


# =======================================================================================
# cosign verify-blob  (no JSON mode — exit code plus exact text)
# =======================================================================================


def parse_verify_blob(exit_code, stdout="", stderr="", registry=None):
    """Classify a `cosign verify-blob` run.

    Success requires BOTH a zero exit code AND exactly the captured success text. A non-zero
    exit with exactly the captured tamper text is `AUT_SIGNATURE_INVALID` — a refusal, and
    reported as one. Everything else is `AUT_OUTPUT_SHAPE_UNKNOWN`: we do not know what
    cosign meant, so it cannot mean "verified".

    The capture does not record which stream carried "Verified OK" (cosign has moved it
    between stdout and stderr across releases), so it is accepted on either — but only when
    the other stream is empty.
    """
    reg = registry or shapes.registry()
    for shapes_set, canonical in ((VERIFY_OK_SHAPES, SHAPE_VERIFY_OK),
                                  (VERIFY_FAIL_SHAPES, SHAPE_VERIFY_FAIL)):
        # Both CONTRACTS must be validated: classifying needs the accept AND the reject text.
        # With only one, an unrecognised failure could look like a success. Each contract has
        # been captured twice (cosign v3.1.2 and v3.1.3, byte-identical output), and one intact
        # capture of each is enough.
        chosen, code, detail = reg.require_any_validated(*shapes_set)
        if chosen is None:
            return C.fail(canonical, code, detail)

    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return C.unknown(SHAPE_VERIFY_OK, f"exit code must be an int, got {exit_code!r}")

    res, out = C.decode_text(stdout or "", SHAPE_VERIFY_OK)
    if res is not None:
        return res
    res, err = C.decode_text(stderr or "", SHAPE_VERIFY_OK)
    if res is not None:
        return res
    out, err = out.strip(), err.strip()

    if exit_code == 0:
        streams = [s for s in (out, err) if s]
        if len(streams) == 1 and streams[0] == VERIFY_OK_TEXT:
            return C.ok(SHAPE_VERIFY_OK, {
                "verdict": "VERIFIED_OK", "exitCode": 0, "text": VERIFY_OK_TEXT})
        return C.unknown(SHAPE_VERIFY_OK,
                         "cosign exited 0 but did not print exactly the captured success "
                         f"text {VERIFY_OK_TEXT!r} (stdout={out[:120]!r} stderr={err[:120]!r}); "
                         "refusing to read unrecognised output as success")

    lines = [ln.strip() for ln in err.splitlines() if ln.strip()]
    if lines == [VERIFY_FAIL_LINE1, VERIFY_FAIL_LINE2]:
        return C.fail(SHAPE_VERIFY_FAIL, R.AUT_SIGNATURE_INVALID,
                      f"cosign verify-blob rejected the signature (exit {exit_code}): "
                      + VERIFY_FAIL_TAIL)
    return C.unknown(SHAPE_VERIFY_FAIL,
                     f"cosign exited {exit_code} with output this kit has not captured "
                     f"(stderr={err[:200]!r}); refusing to classify it")


# =======================================================================================
# binding
# =======================================================================================


def check_binding(bundle_data, decision_digest_hex, shape_id=SHAPE_BUNDLE_KEYED):
    """Does this bundle sign THIS decision digest?

    The gate signs the decision's canonical bytes, whose sha256 IS `Decision.digest()`. So the
    bundle's messageDigest must equal the decision digest exactly. Anything else means the
    signature is about some other artifact and is not evidence here.
    """
    if not isinstance(bundle_data, dict) or "messageDigestHex" not in bundle_data:
        return C.unknown(shape_id, "cannot check binding: bundle was not parsed")
    if not isinstance(decision_digest_hex, str) or not C.hex64(decision_digest_hex):
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"decision digest {decision_digest_hex!r} is not a sha256 hex string")
    got = bundle_data["messageDigestHex"]
    if got != decision_digest_hex:
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      "the signed message digest is not this decision's digest "
                      f"(signed={got[:16]}… decision={decision_digest_hex[:16]}…)")
    return C.ok(shape_id, {
        "kind": "cosign-sign-blob",
        "decisionDigest": decision_digest_hex,
        "signatureB64": bundle_data.get("signatureB64"),
        "logIndex": bundle_data.get("logIndex"),
        "publicKeyHint": bundle_data.get("publicKeyHint"),
    })


__all__ = [
    "KEYED_V03_SHAPES", "SHAPE_BUNDLE_KEYED", "SHAPE_BUNDLE_KEYED_V03", "SHAPE_BUNDLE_KEYLESS",
    "SHAPE_BUNDLE_KEYLESS_LEGACY", "SHAPE_VERIFY_FAIL", "SHAPE_VERIFY_FAIL_V03",
    "SHAPE_VERIFY_OK", "SHAPE_VERIFY_OK_V03", "SHAPE_VERSION", "SUPPORTED_MEDIA_TYPE",
    "VERIFY_FAIL_LINE1", "VERIFY_FAIL_LINE2", "VERIFY_FAIL_SHAPES", "VERIFY_OK_SHAPES",
    "VERIFY_OK_TEXT", "VERSION_GATE", "check_binding", "check_certificate_identity",
    "check_tlog_agreement", "parse_bundle", "parse_keyless_bundle", "parse_verify_blob",
    "parse_version",
]
