"""Rekor transparency-log parsing: the REST entry, `rekor-cli get`, `rekor-cli loginfo`.

This module carries the one piece of real cryptography in the kit: RFC 6962 §2.1.1 Merkle
inclusion-proof verification. That is not "adding cryptographic infrastructure" — it is a
hash-tree walk over SHA-256, the exact computation the proof exists to enable, and without it
an "inclusion proof" is just an array of hex strings nobody checked. It is the only way to
know the entry is really IN the log rather than merely claimed to be.

What is deliberately NOT verified here:

  * the checkpoint signature and the signedEntryTimestamp — verifying those needs Rekor's
    public key and ECDSA. No Rekor key is present in the capture corpus, and fetching or
    hard-coding one would be a new trust root. Their SHAPE is verified instead (DER
    structure, checkpoint layout, and the key hint matching the entry's logID), and the
    parser says plainly that they are unverified.

FRESHNESS. `integratedTime` — the log's own record of when the entry was made — is the
freshness source. Not the file mtime, not the bundle's timestamp, not the local clock.

REKOR-CLI. `rekor-cli get --format json` omits the verification/inclusionProof block by
default. That absence is DETECTED and reported: the CLI shape can establish that an entry
exists, never that it is included. Proof requires the REST shape.
"""
import base64
import binascii
import datetime as _dt

from ...models import reasons as R
from .. import shapes
from . import _common as C

SHAPE_REST = "rekor.rest.entry.v1"
#: The 2026-08-06 REST entry, bound to captures/normalized/bundle_v03.json. SAME serialisation
#: as SHAPE_REST; a second capture, not a second contract. See REST_SHAPES.
SHAPE_REST_FRESH = "rekor.rest.entry.fresh.v1"
#: Both registered captures of the REST entry shape, canonical id first. A parser needs ONE of
#: them validated: tampering with either capture must not take the shape offline.
REST_SHAPES = (SHAPE_REST, SHAPE_REST_FRESH)
SHAPE_REST_LOGINFO = "rekor.rest.loginfo.v1"
SHAPE_CLI_GET = "rekor.cli.get.v1"
SHAPE_CLI_LOGINFO = "rekor.cli.loginfo.v1"

VERSION_GATE = C.VersionGate("rekor-cli", minimum=(1, 5, 0), below=(2, 0, 0),
                             validated="v1.5.3")

#: Entry body kinds present in the real capture corpus: "rekord" in the REST entry,
#: "hashedrekord" in the cosign bundle. Any other kind is an unvalidated contract.
KNOWN_BODY_KINDS = ("rekord", "hashedrekord")

#: 8-byte tree-id prefix + 32-byte leaf hash, hex-encoded.
_UUID_LEN_WITH_PREFIX = 80
_UUID_LEN_BARE = 64


# =======================================================================================
# RFC 6962 inclusion proof
# =======================================================================================


def _merkle_root(leaf_hash, index, tree_size, proof):
    """RFC 6962 §2.1.1. Returns (root_bytes, error_text)."""
    if tree_size <= 0:
        return None, f"tree size {tree_size} is not positive"
    if index < 0 or index >= tree_size:
        return None, f"log index {index} is outside a tree of size {tree_size}"
    fn, sn = index, tree_size - 1
    node = leaf_hash
    for i, sibling in enumerate(proof):
        if sn == 0:
            return None, f"inclusion proof is too long (extra hash at position {i})"
        if len(sibling) != 32:
            return None, f"proof hash {i} is {len(sibling)} bytes, expected 32"
        if (fn & 1) or fn == sn:
            node = C.sha256(b"\x01", sibling, node)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            node = C.sha256(b"\x01", node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None, "inclusion proof is too short for the claimed tree size"
    return node, ""


def verify_inclusion_proof(leaf_hash, log_index, tree_size, hashes, root_hash,
                           encoding="hex", shape_id=SHAPE_REST):
    """Verify a Merkle inclusion proof. Returns a ParseResult; failure is never a warning."""
    decoded = []
    for i, h in enumerate(hashes):
        if encoding == "hex":
            if not C.hex64(h):
                return C.unknown(shape_id, f"inclusion proof hash {i} is not 32-byte hex")
            decoded.append(bytes.fromhex(h))
        else:
            res, raw = C.b64decode_strict(h, f"inclusion proof hash {i}", shape_id)
            if res is not None:
                return res
            decoded.append(raw)

    if encoding == "hex":
        if not C.hex64(root_hash):
            return C.unknown(shape_id, "inclusion proof rootHash is not 32-byte hex")
        expected = bytes.fromhex(root_hash)
    else:
        res, expected = C.b64decode_strict(root_hash, "inclusion proof rootHash", shape_id)
        if res is not None:
            return res

    computed, err = _merkle_root(leaf_hash, log_index, tree_size, decoded)
    if computed is None:
        return C.unknown(shape_id, f"malformed inclusion proof: {err}")
    if computed != expected:
        return C.fail(shape_id, R.AUT_SIGNATURE_INVALID,
                      "inclusion proof does NOT verify: recomputed Merkle root "
                      f"{computed.hex()[:16]}… does not match the claimed root "
                      f"{expected.hex()[:16]}… — the entry is not in this log at that index")
    return C.ok(shape_id, {
        "verified": True, "logIndex": log_index, "treeSize": tree_size,
        "rootHashHex": expected.hex(), "proofLength": len(decoded),
    })


# =======================================================================================
# checkpoint (signed note)
# =======================================================================================


def parse_checkpoint(envelope, shape_id=SHAPE_REST):
    """Parse a signed-note checkpoint: origin / size / root / blank line / signature lines.

    SHAPE ONLY — the signature is not verified (no Rekor public key is in scope). What IS
    checked is that the signature line is a well-formed note signature and that its 4-byte
    key hint is recoverable, so the caller can compare it against the entry's logID.
    """
    res, text = C.decode_text(envelope, shape_id)
    if res is not None:
        return res
    lines = text.split("\n")
    if len(lines) < 5:
        return C.unknown(shape_id, f"checkpoint has {len(lines)} lines; expected at least 5 "
                                   "(origin, size, root, blank, signature)")
    origin, size_text, root_b64 = lines[0], lines[1], lines[2]
    if lines[3] != "":
        return C.unknown(shape_id, "checkpoint is missing the blank separator line")
    if not size_text.isdigit():
        return C.unknown(shape_id, f"checkpoint size line {size_text!r} is not an integer")

    root_res, root = C.b64decode_strict(root_b64, "checkpoint root hash", shape_id)
    if root_res is not None:
        return root_res
    if len(root) != 32:
        return C.unknown(shape_id, f"checkpoint root hash is {len(root)} bytes, expected 32")

    sig_lines = [ln for ln in lines[4:] if ln.strip()]
    if not sig_lines:
        return C.unknown(shape_id, "checkpoint carries no signature line")
    parts = sig_lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "\u2014":   # U+2014 EM DASH, per the signed-note format
        return C.unknown(shape_id,
                         "checkpoint signature line is not the '— <keyname> <base64>' form")
    key_name = parts[1]
    try:
        raw = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        return C.unknown(shape_id, f"checkpoint signature is not base64 ({exc})")
    if len(raw) < 5:
        return C.unknown(shape_id, "checkpoint signature is too short to carry a key hint")
    good, why = C.is_der_ecdsa_signature(raw[4:])
    if not good:
        return C.unknown(shape_id, f"checkpoint signature body is not a DER signature: {why}")

    origin_parts = origin.rsplit(" - ", 1)
    tree_id = origin_parts[1] if len(origin_parts) == 2 and origin_parts[1].isdigit() else None
    return C.ok(shape_id, {
        "origin": origin,
        "logName": origin_parts[0],
        "treeId": tree_id,
        "treeSize": int(size_text),
        "rootHashHex": root.hex(),
        "rootHashB64": root_b64,
        "keyName": key_name,
        "keyHintHex": raw[:4].hex(),
        # The RAW envelope is carried through so the verifier can check the signature against
        # the PINNED Rekor key (authority/trustroot.py). The parser deliberately still does no
        # crypto — separating "what this document says" from "is it authentic" is what keeps
        # the parsers testable against captures. `signatureVerified` stays False HERE and is
        # replaced by the verifier; a parser that claimed verification it had not performed is
        # the exact defect this whole round exists to remove.
        "raw": envelope if isinstance(envelope, str) else None,
        "signatureVerified": False,
        "signatureNote": "checkpoint signature not yet checked at parse time; "
                         "RekorTransparencyVerifier verifies it against the pinned key",
    })


# =======================================================================================
# REST entry
# =======================================================================================


def parse_rest_entry(raw, registry=None):
    """`GET /api/v1/log/entries?logIndex=N` — the proof-bearing, freshness-bearing shape."""
    reg = registry or shapes.registry()
    res, doc = C.load_json(raw, SHAPE_REST)
    if res is not None:
        return res
    good, code, detail, _chosen = shapes.validate_shape_any(doc, REST_SHAPES, reg)
    if not good:
        return C.fail(SHAPE_REST, code, detail)
    if len(doc) != 1:
        return C.unknown(SHAPE_REST,
                         f"{len(doc)} entries in the response; only the single-entry shape "
                         "has been captured")
    uuid, entry = next(iter(doc.items()))

    body_res, body = C.b64decode_strict(entry["body"], "body", SHAPE_REST)
    if body_res is not None:
        return body_res
    body_doc_res, body_doc = C.load_json(body, SHAPE_REST)
    if body_doc_res is not None:
        return body_doc_res
    kind = body_doc.get("kind") if isinstance(body_doc, dict) else None
    if kind not in KNOWN_BODY_KINDS:
        return C.unknown(SHAPE_REST, f"entry body kind {kind!r} is not one of the captured "
                                     f"kinds {KNOWN_BODY_KINDS}")

    # The UUID is the entry's identity: 8-byte tree-id prefix + the leaf hash. Recomputing it
    # proves the body we were handed is the body that was logged under that UUID.
    leaf = C.sha256(b"\x00", body)
    if len(uuid) == _UUID_LEN_WITH_PREFIX:
        tree_prefix, uuid_leaf = uuid[:16], uuid[16:]
    elif len(uuid) == _UUID_LEN_BARE:
        tree_prefix, uuid_leaf = None, uuid
    else:
        return C.unknown(SHAPE_REST, f"entry UUID is {len(uuid)} hex chars; expected 64 or 80")
    if uuid_leaf != leaf.hex():
        return C.fail(SHAPE_REST, R.AUT_BINDING_MISMATCH,
                      f"entry UUID {uuid_leaf[:16]}… is not the hash of the body it is keyed "
                      f"by (computed {leaf.hex()[:16]}…)")

    verification = entry["verification"]
    proof = verification["inclusionProof"]

    # --- SHARDING. The one thing the 2021 capture got wrong by accident ------------------
    # This used to require proof.logIndex == entry.logIndex, and that passed for three
    # releases because the only proof-carrying REST entry in the corpus was logIndex 1000000,
    # an entry old enough to predate every shard split, where the two ARE equal.
    # rekor_rest_entry_fresh.json (global 2354787700, shard-local 2232883438) disproves it:
    # the entry-level logIndex is GLOBAL across every shard the log has ever had, while
    # inclusionProof.logIndex is LOCAL to the ACTIVE shard's Merkle tree. Requiring equality
    # was not a security check that has now been relaxed — it was a coincidence of one
    # fixture, and enforcing it would reject every entry Rekor has issued since its first
    # shard split.
    #
    # What actually binds this proof to this entry is unchanged and is checked above and
    # below: leaf == sha256(0x00 || body), the UUID is that leaf, and the Merkle recomputation
    # runs at the shard-local index inside the shard-local tree. What replaces the equality is
    # the true invariant plus a place to check it: the offset must be non-negative, and
    # `check_shard_offset` proves it equals the sum of the inactive shards' sizes as soon as
    # the caller supplies GET /api/v1/log. Strictly more checking than before, not less.
    shard_offset = entry["logIndex"] - proof["logIndex"]
    if shard_offset < 0:
        return C.unknown(SHAPE_REST,
                         f"inclusionProof.logIndex {proof['logIndex']} is AHEAD of the entry's "
                         f"global logIndex {entry['logIndex']}; a shard-local index can never "
                         "exceed the global one")
    if proof["logIndex"] >= proof["treeSize"]:
        return C.unknown(SHAPE_REST,
                         f"inclusionProof.logIndex {proof['logIndex']} is outside its own tree "
                         f"of size {proof['treeSize']}")

    proof_res = verify_inclusion_proof(
        leaf_hash=leaf, log_index=proof["logIndex"], tree_size=proof["treeSize"],
        hashes=proof["hashes"], root_hash=proof["rootHash"], encoding="hex",
        shape_id=SHAPE_REST)
    if not proof_res.ok:
        return proof_res

    cp_res = parse_checkpoint(proof["checkpoint"], SHAPE_REST)
    if not cp_res.ok:
        return cp_res
    checkpoint = cp_res.data
    if checkpoint["rootHashHex"] != proof["rootHash"] or \
            checkpoint["treeSize"] != proof["treeSize"]:
        return C.unknown(SHAPE_REST,
                         "checkpoint root/size does not match the inclusion proof it signs "
                         f"(checkpoint {checkpoint['rootHashHex'][:16]}…/"
                         f"{checkpoint['treeSize']} vs proof {proof['rootHash'][:16]}…/"
                         f"{proof['treeSize']})")
    if checkpoint["keyHintHex"] != entry["logID"][:8]:
        return C.unknown(SHAPE_REST,
                         f"checkpoint key hint {checkpoint['keyHintHex']} does not match the "
                         f"entry's logID prefix {entry['logID'][:8]}")
    if tree_prefix is not None and checkpoint["treeId"] is not None:
        if f"{int(checkpoint['treeId']):016x}" != tree_prefix:
            return C.unknown(SHAPE_REST,
                             f"checkpoint origin tree id {checkpoint['treeId']} does not match "
                             f"the UUID tree prefix {tree_prefix}")

    set_res, set_raw = C.b64decode_strict(verification["signedEntryTimestamp"],
                                          "signedEntryTimestamp", SHAPE_REST)
    if set_res is not None:
        return set_res
    good_der, why = C.is_der_ecdsa_signature(set_raw)
    if not good_der:
        return C.unknown(SHAPE_REST, f"signedEntryTimestamp is not a DER signature: {why}")

    return C.ok(SHAPE_REST, {
        "uuid": uuid,
        "logIndex": entry["logIndex"],
        "logIdHex": entry["logID"],
        "integratedTime": entry["integratedTime"],
        "kind": kind,
        "bodyDataHash": _body_data_hash(body_doc),
        "bodyB64": entry["body"],
        "leafHashHex": leaf.hex(),
        "inclusionProofVerified": True,
        "proofLogIndex": proof["logIndex"],
        "shardOffset": shard_offset,
        "shardOffsetVerified": False,
        "shardOffsetNote": (
            "logIndex is GLOBAL, inclusionProof.logIndex is SHARD-LOCAL; their difference is "
            "the total size of the log's inactive shards. Supply GET /api/v1/log "
            "(rekor.restLogInfo) and check_shard_offset proves it."),
        "treeSize": proof["treeSize"],
        "rootHashHex": proof["rootHash"],
        "checkpoint": checkpoint,
        "signedEntryTimestamp": {
            "present": True, "derBytes": len(set_raw), "verified": False,
            "note": "SET SHAPE checked here; the Rekor key IS pinned in authority/trustroot.py "
                    "and the CHECKPOINT signature is verified by RekorTransparencyVerifier. "
                    "Verifying the SET itself additionally requires canonicalising the entry "
                    "body, which is not yet implemented — so this field stays False.",
        },
    })


def _body_data_hash(body_doc):
    try:
        spec = body_doc["spec"]
        return dict(spec["data"]["hash"])
    except (KeyError, TypeError):
        return None


# =======================================================================================
# REST loginfo  (GET /api/v1/log) — the shard map
# =======================================================================================


def parse_rest_loginfo(raw, registry=None):
    """`GET /api/v1/log` — the active signed tree head plus the sealed inactive shards.

    Registered as its own shape because it is a genuinely different document from
    `rekor-cli loginfo`: the CLI rendering reports ActiveTreeSize/TotalTreeSize and does NOT
    enumerate the shards, so it cannot support the shard-offset check.
    """
    reg = registry or shapes.registry()
    res, doc = C.load_json(raw, SHAPE_REST_LOGINFO)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_REST_LOGINFO, reg)
    if not good:
        return C.fail(SHAPE_REST_LOGINFO, code, detail)

    cp_res = parse_checkpoint(doc["signedTreeHead"], SHAPE_REST_LOGINFO)
    if not cp_res.ok:
        return cp_res
    checkpoint = cp_res.data
    if checkpoint["rootHashHex"] != doc["rootHash"] or checkpoint["treeSize"] != doc["treeSize"]:
        return C.unknown(SHAPE_REST_LOGINFO,
                         "the signed tree head disagrees with the rootHash/treeSize it is "
                         f"attached to (head {checkpoint['rootHashHex'][:16]}…/"
                         f"{checkpoint['treeSize']} vs body {doc['rootHash'][:16]}…/"
                         f"{doc['treeSize']})")
    if checkpoint["treeId"] is not None and checkpoint["treeId"] != doc["treeID"]:
        return C.unknown(SHAPE_REST_LOGINFO,
                         f"signed tree head origin names tree {checkpoint['treeId']} but the "
                         f"document says {doc['treeID']}")

    shards = []
    for i, shard in enumerate(doc.get("inactiveShards") or ()):
        s_res = parse_checkpoint(shard["signedTreeHead"], SHAPE_REST_LOGINFO)
        if not s_res.ok:
            return s_res
        head = s_res.data
        if head["rootHashHex"] != shard["rootHash"] or head["treeSize"] != shard["treeSize"]:
            return C.unknown(SHAPE_REST_LOGINFO,
                             f"inactiveShards[{i}] signed tree head disagrees with its own "
                             "rootHash/treeSize")
        shards.append({"treeId": shard["treeID"], "treeSize": shard["treeSize"],
                       "rootHashHex": shard["rootHash"]})

    return C.ok(SHAPE_REST_LOGINFO, {
        "treeId": doc["treeID"],
        "activeTreeSize": doc["treeSize"],
        "rootHashHex": doc["rootHash"],
        "checkpoint": checkpoint,
        "inactiveShards": shards,
        "inactiveTotalSize": sum(s["treeSize"] for s in shards),
        "signatureVerified": False,
        "signatureNote": "shape checked at parse time; the signature is VERIFIED against the "
                         "pinned Rekor key by RekorTransparencyVerifier, which refuses the "
                         "entry when it does not check out",
    })


def check_shard_offset(entry_data, loginfo_data, shape_id=SHAPE_REST):
    """Prove the gap between an entry's GLOBAL logIndex and its SHARD-LOCAL proof index.

    `entry.logIndex - inclusionProof.logIndex` must be exactly the number of leaves sealed into
    the log's inactive shards. Anything else means the entry and the proof are describing
    different positions, which is the failure the old equality check was reaching for and never
    actually able to detect on a sharded log.

    The entry's checkpoint must also come from the ACTIVE tree: a proof recomputed against a
    retired shard's root would verify internally and prove nothing about the live log.
    """
    if not isinstance(entry_data, dict) or "shardOffset" not in entry_data:
        return C.unknown(shape_id, "cannot check the shard offset: no REST entry was parsed")
    if not isinstance(loginfo_data, dict) or "inactiveTotalSize" not in loginfo_data:
        return C.unknown(shape_id,
                         "cannot check the shard offset: GET /api/v1/log was not supplied. "
                         "Configure rekor.restLogInfo.")
    offset = entry_data["shardOffset"]
    expected = loginfo_data["inactiveTotalSize"]
    if offset != expected:
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"the entry's global logIndex is {offset} ahead of its shard-local "
                      f"inclusionProof.logIndex, but the log's inactive shards hold "
                      f"{expected} leaves. The entry and the proof are not describing the same "
                      "position in the same log.")
    entry_tree = (entry_data.get("checkpoint") or {}).get("treeId")
    if entry_tree is not None and entry_tree != loginfo_data["treeId"]:
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"the entry's inclusion proof is against tree {entry_tree}, but the "
                      f"ACTIVE tree is {loginfo_data['treeId']}; a proof against a retired "
                      "shard says nothing about the live log")
    if entry_data.get("treeSize", 0) > loginfo_data["activeTreeSize"]:
        return C.fail(shape_id, R.AUT_BINDING_MISMATCH,
                      f"the entry's proof claims a tree of {entry_data['treeSize']} leaves but "
                      f"the log's active tree has only {loginfo_data['activeTreeSize']}; the "
                      "proof is from a future the log has not reached")
    return C.ok(shape_id, {
        "shardOffset": offset,
        "inactiveTotalSize": expected,
        "inactiveShards": list(loginfo_data["inactiveShards"]),
        "activeTreeId": loginfo_data["treeId"],
        "shardOffsetVerified": True,
    })


# =======================================================================================
# rekor-cli
# =======================================================================================


def parse_cli_get(raw, rekor_version=None, registry=None):
    """`rekor-cli get --log-index N --format json`.

    Succeeds — but the returned data says `inclusionProofPresent: False`, because the CLI
    omits the verification block by default. `require_inclusion_proof` turns that into the
    refusal it must be for anyone who needs a proof.
    """
    reg = registry or shapes.registry()
    if rekor_version is not None:
        supported, code, detail = VERSION_GATE.check(rekor_version)
        if not supported:
            return C.fail(SHAPE_CLI_GET, code, detail)
    res, doc = C.load_json(raw, SHAPE_CLI_GET)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_CLI_GET, reg)
    if not good:
        return C.fail(SHAPE_CLI_GET, code, detail)

    body = doc["Body"]
    kinds = [k for k in body if isinstance(body[k], dict)]
    if len(kinds) != 1:
        return C.unknown(SHAPE_CLI_GET,
                         f"Body carries {len(kinds)} entry objects; expected exactly one")
    obj_key = kinds[0]
    kind = obj_key[:-3].lower() if obj_key.endswith("Obj") else obj_key.lower()
    if kind not in KNOWN_BODY_KINDS:
        return C.unknown(SHAPE_CLI_GET, f"Body kind {obj_key!r} is not one of the captured "
                                        f"kinds {KNOWN_BODY_KINDS}")

    verification = doc.get("Verification") or {}
    proof_present = bool(verification.get("InclusionProof"))
    return C.ok(SHAPE_CLI_GET, {
        "logIndex": doc["LogIndex"],
        "integratedTime": doc["IntegratedTime"],
        "uuid": doc["UUID"],
        "logIdHex": doc["LogID"],
        "kind": kind,
        "bodyDataHash": _cli_data_hash(body[obj_key]),
        "inclusionProofPresent": proof_present,
        "note": "rekor-cli omits Verification/InclusionProof by default; the REST shape is "
                "required for a proof",
    })


def _cli_data_hash(obj):
    try:
        return dict(obj["data"]["hash"])
    except (KeyError, TypeError):
        return None


def require_inclusion_proof(cli_data, shape_id=SHAPE_CLI_GET):
    """Refuse a rekor-cli record that carries no inclusion proof. Called by anything that
    needs proof rather than mere existence."""
    if isinstance(cli_data, dict) and cli_data.get("inclusionProofPresent"):
        return C.ok(shape_id, cli_data)
    return C.unknown(shape_id,
                     "rekor-cli output carries no Verification/InclusionProof block (it is "
                     "omitted by default), so inclusion cannot be proved from it. Fetch the "
                     "REST entry (GET /api/v1/log/entries?logIndex=N) instead.")


def parse_loginfo(raw, rekor_version=None, registry=None):
    """`rekor-cli loginfo --format json` — the signed tree head summary."""
    reg = registry or shapes.registry()
    if rekor_version is not None:
        supported, code, detail = VERSION_GATE.check(rekor_version)
        if not supported:
            return C.fail(SHAPE_CLI_LOGINFO, code, detail)
    res, doc = C.load_json(raw, SHAPE_CLI_LOGINFO)
    if res is not None:
        return res
    good, code, detail = shapes.validate_shape(doc, SHAPE_CLI_LOGINFO, reg)
    if not good:
        return C.fail(SHAPE_CLI_LOGINFO, code, detail)
    if doc["ActiveTreeSize"] > doc["TotalTreeSize"]:
        return C.unknown(SHAPE_CLI_LOGINFO,
                         "ActiveTreeSize exceeds TotalTreeSize; incoherent log state")
    return C.ok(SHAPE_CLI_LOGINFO, {
        "activeTreeSize": doc["ActiveTreeSize"],
        "totalTreeSize": doc["TotalTreeSize"],
        "rootHashHex": doc["RootHash"],
        "treeId": doc["TreeID"],
    })


# =======================================================================================
# freshness
# =======================================================================================


def freshness(entry_data, max_age_seconds, now=None, shape_id=SHAPE_REST):
    """`integratedTime` is the freshness source. The LOG's clock, not ours and not the file's.

    A future-dated entry is refused as hard as an expired one: a timestamp ahead of the real
    clock is either a broken log or a forged record, and neither is fresh evidence.
    """
    if not isinstance(entry_data, dict) or "integratedTime" not in entry_data:
        return C.unknown(shape_id, "cannot judge freshness: no integratedTime was parsed")
    integrated = entry_data["integratedTime"]
    if not isinstance(integrated, int) or isinstance(integrated, bool) or integrated <= 0:
        return C.unknown(shape_id, f"integratedTime {integrated!r} is not a positive integer")
    reference = now if now is not None else _now_epoch()
    age = reference - integrated
    if age < 0:
        return C.fail(shape_id, R.AUT_FRESHNESS_EXPIRED,
                      f"transparency-log entry is dated {-age}s in the FUTURE "
                      f"(integratedTime={integrated}); refusing forward-dated evidence")
    if age > max_age_seconds:
        return C.fail(shape_id, R.AUT_FRESHNESS_EXPIRED,
                      f"transparency-log entry is {age}s old, over the {max_age_seconds}s "
                      f"limit (integratedTime={integrated}); it is not evidence about this run")
    return C.ok(shape_id, {
        "source": "rekor.integratedTime",
        "integratedTime": integrated,
        "ageSeconds": age,
        "maxAgeSeconds": max_age_seconds,
        "logIndex": entry_data.get("logIndex"),
    })


def _now_epoch():
    """The REAL wall clock, deliberately not `util.clock.utcnow_iso()`.

    `utcnow_iso` honours SHIPGATE_SOURCE_DATE_EPOCH so decisions can be reproducible. Using it
    for freshness would let a pinned build clock make stale evidence look fresh, which is the
    exact trick `util.clock` warns about.
    """
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


__all__ = [
    "KNOWN_BODY_KINDS", "REST_SHAPES", "SHAPE_CLI_GET", "SHAPE_CLI_LOGINFO", "SHAPE_REST",
    "SHAPE_REST_FRESH", "SHAPE_REST_LOGINFO", "VERSION_GATE", "check_shard_offset", "freshness",
    "parse_checkpoint", "parse_cli_get", "parse_loginfo", "parse_rest_entry",
    "parse_rest_loginfo", "require_inclusion_proof", "verify_inclusion_proof",
]
