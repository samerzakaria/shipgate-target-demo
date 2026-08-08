"""Loader for the capture corpus, plus the adversarial mutations built from it.

Two kinds of fixture, and the difference is load-bearing:

  REAL CAPTURES  `captures/raw/` (byte-exact as received) and `captures/normalized/` (UTF-8).
                 These are the ONLY inputs a shape may be validated against. THREE encodings
                 are represented: plain UTF-8, UTF-16LE+BOM (four gh files redirected from
                 PowerShell) and UTF-8+BOM (the 2026-08-05 round). `raw` keeps all of it,
                 which is what makes the BOM handling testable rather than theoretical.

                 Four of them are SANITIZED (see SANITIZED_CAPTURES): the capture author
                 replaced repository and account names with OWNER/REPO. One consequence is
                 load-bearing and must not be smoothed over — the keyless bundle's Fulcio
                 certificate carries the ORIGINAL name inside signed DER, so an identity check
                 comparing the two WILL disagree. That is a correct parser meeting a sanitized
                 fixture, and the fix is to record it, not to loosen the check.

  SYNTHETIC      `tests_data/`, every filename prefixed `SYNTHETIC-ADVERSARIAL__`. Loading one
                 REQUIRES the prefix, so a hand-authored file cannot be passed off as a
                 capture even by accident.

The mutations are generated FROM the real captures rather than stored, so they cannot drift
away from the thing they are supposed to be a corruption of. Each carries the reason code the
parser must answer with, which is what makes "rejects a mutated copy" a checkable claim
instead of a promise.
"""
import base64
import os
from typing import Dict, List, Tuple

from ..models import reasons as R
from . import shapes

TESTS_DATA_DIR = shapes.TESTS_DATA_DIR
SYNTHETIC_PREFIX = shapes.SYNTHETIC_PREFIX


def __getattr__(name):
    """`RAW_DIR` / `NORMALIZED_DIR`, forwarded to the lazy ones in `shapes`.

    These were module constants bound at import. Binding them here again would defeat the
    laziness — importing `fixtures` would extract the corpus — so the module hook forwards
    instead, and only a caller that actually reads the attribute pays for it.
    """
    if name in ("RAW_DIR", "NORMALIZED_DIR"):
        return getattr(shapes, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

#: Every capture file, by the shape it is a capture OF. None = documentation, not a shape.
CAPTURE_FILES: Dict[str, str] = {
    "cosign_version.json": "cosign.version.v1",
    "cosign_signblob_bundle.json": "cosign.bundle.keyed.v0_3",
    "cosign_verify_ok.txt": "cosign.verifyblob.ok.v1",
    "cosign_verify_fail.txt": "cosign.verifyblob.fail.v1",
    "rekor_rest_entry.json": "rekor.rest.entry.v1",
    "rekor_get_logindex.json": "rekor.cli.get.v1",
    "rekor_loginfo.json": "rekor.cli.loginfo.v1",
    "repo.json": "gh.repo.v1",
    "env_one.json": "gh.environment.v1",
    "env_list.json": "gh.environment.list.v1",
    "env_secrets.json": "gh.environment.secrets.v1",
    # --- the 2026-08-05 shape-capture round (sanitized; see SHAPES.json) ---------------
    "oidc_claims.json": "oidc.github.claims.v1",
    "cosign_keyless_bundle.json": "cosign.bundle.keyless.legacy.v1",
    "env_protected_one.json": "gh.environment.protected.v1",
    "env_protected_list.json": "gh.environment.list.v1",
    # --- the 2026-08-06 v0.3 round (cosign v3.1.3, live against public Sigstore) ---------
    "bundle_v03.json": "cosign.bundle.v0_3.keyed",
    "cosign_version_3_1_3.json": "cosign.version.v1",
    "verify_v03_ok.txt": "cosign.verifyblob.v03.ok.v1",
    "verify_v03_fail.txt": "cosign.verifyblob.v03.fail.v1",
    "rekor_rest_entry_fresh.json": "rekor.rest.entry.fresh.v1",
    "rekor_loginfo_fresh.json": "rekor.rest.loginfo.v1",
}

#: Captures whose SHAPE is validated but whose IDENTITY does not bind to anything, because
#: the capture author sanitized the JSON to OWNER/REPO. `cosign_keyless_bundle.json` is the
#: sharp case: its Fulcio certificate carries the ORIGINAL repository inside signed DER,
#: which no sanitiser could reach, so a correct identity check MUST disagree with the
#: surrounding JSON. The kit reports that disagreement instead of relaxing the check.
SANITIZED_CAPTURES = {
    "oidc_claims.json": "repository/actor strings sanitized to OWNER/REPO",
    "cosign_keyless_bundle.json": (
        "JSON sanitized to OWNER/REPO, but the Fulcio cert SAN still says "
        "samerzakaria/shipgate-shape-capture — shapeValidated:true, bindingValidated:false"),
    "env_protected_one.json": "repository and reviewer login sanitized to OWNER",
    "env_protected_list.json": "repository and reviewer login sanitized to OWNER",
}

#: The repository the keyless certificate's signed DER actually names. Not sanitizable.
CERT_REPOSITORY = "samerzakaria/shipgate-shape-capture"

#: The moment the keyless signature was logged. Freshness and token liveness are judged at
#: THIS instant, never at "now" — a recorded 5-minute token is always expired by now.
KEYLESS_SIGNED_AT = 1785949299

#: Present in the corpus, parsed by nobody: provenance documentation, the public half of the
#: throwaway signing key, and the impossibility evidence for the one shape still BLOCKED.
DOC_FILES = ("PROVENANCE.txt", "PROVENANCE_shapes.txt", "_NOTE_protected_env.txt",
             "PROVENANCE_v03.txt", "SHA256SUMS.txt", "cosign.pub", "keyless_attempt.txt")

#: Why no unattended capture of the v0.3 KEYLESS bundle is possible. cosign without --key needs
#: an OIDC token; with none it falls back to a device-code flow and waits for a human at a
#: browser. Digest-pinned in SHAPES.json under `blockedEvidence` and re-hashed at load. This is
#: evidence of IMPOSSIBILITY: it validates nothing and can never promote a shape.
KEYLESS_ATTEMPT_FILE = "keyless_attempt.txt"
KEYLESS_ATTEMPT_MARKER = "Non-interactive mode detected, using device flow."

#: The moment bundle_v03.json's signature was integrated into the log. Freshness for the
#: 2026-08-06 round is judged at THIS instant, never at "now": the entry was ~29 minutes old
#: when it was registered and ages past the 3600s default about half an hour later, so a
#: selfcheck asserting "fresh against the wall clock" would pass on the day it was written and
#: fail forever after. That is a worse test than no test.
FRESH_INTEGRATED_AT = 1785990048

#: The log entry bundle_v03.json and rekor_rest_entry_fresh.json both describe.
FRESH_LOG_INDEX = 2354787700
#: Its SHARD-LOCAL inclusion-proof index, and the offset between the two. Rekor's entry-level
#: logIndex is global across every shard the log has ever had.
FRESH_PROOF_LOG_INDEX = 2232883438
FRESH_SHARD_OFFSET = FRESH_LOG_INDEX - FRESH_PROOF_LOG_INDEX      # == 4163431 + 117740831

#: Files that arrived UTF-16LE+BOM. `raw` and `normalized` differ for exactly these.
UTF16_RAW_FILES = ("repo.json", "env_one.json", "env_list.json", "env_secrets.json",
                   "_NOTE_protected_env.txt")

#: Files that arrived UTF-8 with a BOM (the 2026-08-05 round). A THIRD encoding in the corpus,
#: which is why `_common.decode_text` handles BOMs as a first-class case rather than a fixup.
UTF8_BOM_RAW_FILES = ("oidc_claims.json", "cosign_keyless_bundle.json",
                      "env_protected_one.json", "env_protected_list.json",
                      "PROVENANCE_shapes.txt")


class FixtureError(LookupError):
    """A fixture is missing or mislabelled. Always fatal — never substituted."""


# ---------------------------------------------------------------------------------------
# real captures
# ---------------------------------------------------------------------------------------


def raw_path(name):
    """A real filesystem path, materialized from the archive. For callers that need a file."""
    from . import capturestore
    return os.path.join(capturestore.variant_dir(capturestore.RAW), name)


def normalized_path(name):
    from . import capturestore
    return os.path.join(capturestore.variant_dir(capturestore.NORMALIZED), name)


def load_raw(name) -> bytes:
    """Byte-exact, as the tool wrote it. BOMs and CRLFs intact — that is the point."""
    return _capture("raw", name)


def load_normalized(name) -> bytes:
    """The UTF-8 copy. This is the only variant a shape may be VALIDATED from."""
    return _capture("normalized", name)


def _capture(variant, name) -> bytes:
    from . import capturestore
    try:
        return capturestore.read(variant, name)
    except capturestore.CaptureStoreError as exc:
        raise FixtureError(str(exc)) from None


def load_text(name, variant="normalized") -> str:
    data = load_raw(name) if variant == "raw" else load_normalized(name)
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"),
                     (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(enc)
    return data.decode("utf-8")


def normalized_dir():
    """The materialized `normalized/` directory. Only the evidenceDir callers need this."""
    from . import capturestore
    return capturestore.variant_dir(capturestore.NORMALIZED)


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise FixtureError(f"capture unreadable: {path} ({exc.strerror or exc})") from None


def positives(variant="normalized") -> List[Tuple[str, str, bytes]]:
    """[(shape_id, filename, data)] for every real capture. The accept set."""
    load = load_raw if variant == "raw" else load_normalized
    return [(shape_id, name, load(name)) for name, shape_id in sorted(CAPTURE_FILES.items())]


def synthetic(name) -> bytes:
    """Load a hand-authored adversarial fixture. REFUSES anything without the prefix."""
    if not name.startswith(SYNTHETIC_PREFIX):
        raise FixtureError(
            f"{name!r} does not start with {SYNTHETIC_PREFIX!r}. Hand-authored fixtures must "
            "be unmistakable; a file that could be read as a real capture is not allowed.")
    return _read(os.path.join(TESTS_DATA_DIR, name))


def synthetic_names() -> List[str]:
    try:
        return sorted(n for n in os.listdir(TESTS_DATA_DIR) if n.startswith(SYNTHETIC_PREFIX))
    except OSError:
        return []


#: REAL INPUT fixtures for the gh attestation positive control, one JSON container because a
#: skill package may not hold a nested archive. Distinct from SYNTHETIC on purpose: these are
#: exact real bytes (artifact, GitHub-produced bundle, Sigstore trusted root), and distinct
#: from captures/ on purpose too — the corpus holds what tools PRINTED; these are what a tool
#: is GIVEN.
REAL_FIXTURES_CONTAINER = "REAL-FIXTURE__gh_attestation_inputs.json"

_real_fixture_dir = None


def real_fixture_path(name) -> str:
    """Materialize one real input fixture to disk and return its path.

    The entry's sha256 is RECOMPUTED from the decoded bytes on every materialization; a
    mismatch raises rather than handing a test a file that is not what the container says
    it is. The directory is per-process and cleaned at exit, like capturestore's.
    """
    import atexit
    import base64
    import hashlib
    import json
    import shutil
    import tempfile
    global _real_fixture_dir
    container_path = os.path.join(TESTS_DATA_DIR, REAL_FIXTURES_CONTAINER)
    with open(container_path, "r", encoding="utf-8") as fh:
        container = json.load(fh)
    entry = (container.get("entries") or {}).get(name)
    if entry is None:
        raise FixtureError(f"{name!r} is not in {REAL_FIXTURES_CONTAINER}; entries: "
                           f"{sorted(container.get('entries') or {})}")
    data = base64.b64decode(entry["b64"], validate=True)
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry["sha256"]:
        raise FixtureError(
            f"{name}: container records sha256 {entry['sha256']} but the payload decodes "
            f"to {actual}; the fixture container has been edited")
    if _real_fixture_dir is None:
        _real_fixture_dir = tempfile.mkdtemp(prefix="shipgate-real-fixtures-")
        atexit.register(shutil.rmtree, _real_fixture_dir, True)
    path = os.path.join(_real_fixture_dir, name)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)
    return path


# ---------------------------------------------------------------------------------------
# mutations — the reject set
# ---------------------------------------------------------------------------------------


def flip_byte(data: bytes, needle: bytes, offset: int = 0) -> bytes:
    """Flip one bit inside the first occurrence of `needle`. The smallest possible tamper."""
    index = data.find(needle)
    if index < 0:
        raise FixtureError(f"cannot mutate: {needle[:32]!r} not present in the capture")
    pos = index + offset
    out = bytearray(data)
    out[pos] ^= 0x01
    return bytes(out)


def flip_signature_byte(data: bytes, field: bytes) -> bytes:
    """Flip a bit in the base64 payload that follows `field`, i.e. inside a signature."""
    index = data.find(field)
    if index < 0:
        raise FixtureError(f"cannot mutate: {field!r} not present in the capture")
    start = data.find(b'"', index + len(field)) + 1
    if start <= 0:
        raise FixtureError(f"cannot locate the value after {field!r}")
    return flip_byte(data, data[start:start + 8], 4)


def truncate(data: bytes, keep: float = 0.6) -> bytes:
    return data[:max(1, int(len(data) * keep))]


def duplicate_key(data: bytes, key: bytes) -> bytes:
    """Insert a second copy of `key` — the parser-differential test."""
    index = data.find(key)
    if index < 0:
        raise FixtureError(f"cannot duplicate: {key!r} not present in the capture")
    end = data.find(b",", index)
    if end < 0:
        end = data.find(b"}", index)
    if end < 0:
        raise FixtureError(f"cannot find the end of the {key!r} member")
    member = data[index:end]
    return data[:end] + b"," + member + data[end:]


def rewrite(data: bytes, old: bytes, new: bytes) -> bytes:
    if old not in data:
        raise FixtureError(f"cannot rewrite: {old!r} not present in the capture")
    return data.replace(old, new, 1)


def rejections() -> List[Dict[str, object]]:
    """The full reject set: [{label, shape, data, expect}].

    `expect` is the reason code the parser MUST answer with. Every entry is derived from a
    real capture, so a change to the corpus changes the mutations too.
    """
    cases = []

    def add(label, shape, data, expect):
        cases.append({"label": label, "shape": shape, "data": data, "expect": expect})

    # --- cosign version -----------------------------------------------------------------
    version = load_normalized("cosign_version.json")
    add("cosign_version:truncated", "cosign.version.v1", truncate(version),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("cosign_version:duplicate_key", "cosign.version.v1",
        duplicate_key(version, b'"gitVersion"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("cosign_version:unsupported_old", "cosign.version.v1",
        rewrite(version, b'"v3.1.2"', b'"v2.2.4"'), R.AUT_TOOL_VERSION_UNSUPPORTED)
    add("cosign_version:unsupported_new", "cosign.version.v1",
        rewrite(version, b'"v3.1.2"', b'"v4.0.0"'), R.AUT_TOOL_VERSION_UNSUPPORTED)
    add("cosign_version:dirty_tree", "cosign.version.v1",
        rewrite(version, b'"clean"', b'"dirty"'), R.AUT_TOOL_VERSION_UNSUPPORTED)
    add("cosign_version:unknown_field", "cosign.version.v1",
        rewrite(version, b'"compiler"', b'"kompiler"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- cosign bundle ------------------------------------------------------------------
    bundle = load_normalized("cosign_signblob_bundle.json")
    add("bundle:truncated", "cosign.bundle.keyed.v0_3", truncate(bundle),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("bundle:duplicate_key", "cosign.bundle.keyed.v0_3",
        duplicate_key(bundle, b'"mediaType"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("bundle:signature_byte_flipped", "cosign.bundle.keyed.v0_3",
        flip_signature_byte(bundle, b'"messageSignature":{"messageDigest":'
                                    b'{"algorithm":"SHA2_256","digest":"p0LSFKnix3qq'
                                    b'IY5BGQH/MJ5ht/iwOY/a60jJem9T2yo="},"signature":'),
        R.AUT_SIGNATURE_INVALID)
    # A byte flipped in the logged body decodes to a still-parseable envelope with a renamed
    # key, so the ENVELOPE check catches it before the Merkle proof gets a chance. The proof
    # itself is exercised by bundle:proof_hash_flipped and bundle:root_hash_swapped.
    add("bundle:tlog_body_byte_flipped", "cosign.bundle.keyed.v0_3",
        flip_signature_byte(bundle, b'"canonicalizedBody":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("bundle:logged_digest_swapped", "cosign.bundle.keyed.v0_3",
        _rewrite_keyed_body(bundle, ("data", "hash", "value"), "b" * 64),
        R.AUT_BINDING_MISMATCH)
    add("bundle:proof_hash_flipped", "cosign.bundle.keyed.v0_3",
        flip_byte(bundle, b'"jVkAyBmVx47nzR9tiGEaFbarK/1w6t+co3UowQomsAU="', 2),
        R.AUT_SIGNATURE_INVALID)
    add("bundle:root_hash_swapped", "cosign.bundle.keyed.v0_3",
        rewrite(bundle, b'"rootHash":"g82TmsPFRQSIqCD0ok0IqN1hG1J/I/XCudHW6xidobM="',
                b'"rootHash":"g82TmsPFRQSIqCD0ok0IqN1hG1J/I/XCudHW6xidobO="'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("bundle:media_type_v0_1", "cosign.bundle.keyed.v0_3",
        rewrite(bundle, b"bundle.v0.3+json", b"bundle.v0.1+json"), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("bundle:key_hint_swapped", "cosign.bundle.keyed.v0_3",
        rewrite(bundle, b'"hint":"qvgoDXvfFUAHjhcvpcpJurfVcULvQ3VLjhApPxKUGl0="',
                b'"hint":"qvgoDXvfFUAHjhcvpcpJurfVcULvQ3VLjhApPxKUGl1="'),
        R.AUT_SIGNATURE_INVALID)
    add("bundle:keyless_shape", "cosign.bundle.keyless.v0_3",
        rewrite(bundle, b'"publicKey":{"hint"',
                b'"certificate":{"rawBytes":"MIIB"},"publicKey":{"hint"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- rekor REST ---------------------------------------------------------------------
    rest = load_normalized("rekor_rest_entry.json")
    add("rekor_rest:truncated", "rekor.rest.entry.v1", truncate(rest),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_rest:duplicate_key", "rekor.rest.entry.v1",
        duplicate_key(rest, b'"integratedTime"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_rest:body_byte_flipped", "rekor.rest.entry.v1",
        flip_signature_byte(rest, b'"body":'), R.AUT_BINDING_MISMATCH)
    add("rekor_rest:proof_hash_flipped", "rekor.rest.entry.v1",
        rewrite(rest, b'"9fa717572d7f9703695fd747e5292109bda1319ce8f2c969f39fe841d65c7c6b"',
                b'"9fa717572d7f9703695fd747e5292109bda1319ce8f2c969f39fe841d65c7c6c"'),
        R.AUT_SIGNATURE_INVALID)
    add("rekor_rest:root_hash_swapped", "rekor.rest.entry.v1",
        rewrite(rest, b'"rootHash":"4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d'
                      b'6a2f3239"',
                b'"rootHash":"4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d'
                b'6a2f323a"'),
        R.AUT_SIGNATURE_INVALID)
    add("rekor_rest:log_id_swapped", "rekor.rest.entry.v1",
        rewrite(rest, b'"logID":"c0d23d6a', b'"logID":"c0d23d6b'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_rest:no_verification_block", "rekor.rest.entry.v1",
        rewrite(rest, b'"verification":', b'"verificationX":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_rest:set_not_der", "rekor.rest.entry.v1",
        rewrite(rest, b'"signedEntryTimestamp":"MEUCID', b'"signedEntryTimestamp":"MUUCID'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- rekor CLI ----------------------------------------------------------------------
    cli = load_normalized("rekor_get_logindex.json")
    add("rekor_cli:truncated", "rekor.cli.get.v1", truncate(cli), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_cli:duplicate_key", "rekor.cli.get.v1", duplicate_key(cli, b'"LogIndex"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_cli:unknown_kind", "rekor.cli.get.v1", rewrite(cli, b'"RekordObj"', b'"WatObj"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    info = load_normalized("rekor_loginfo.json")
    add("rekor_loginfo:truncated", "rekor.cli.loginfo.v1", truncate(info),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("rekor_loginfo:short_root", "rekor.cli.loginfo.v1",
        rewrite(info, b'"RootHash":"d6204512', b'"RootHash":"d620451'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- gh -----------------------------------------------------------------------------
    repo = load_normalized("repo.json")
    add("gh_repo:truncated", "gh.repo.v1", truncate(repo), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("gh_repo:duplicate_key", "gh.repo.v1", duplicate_key(repo, b'"full_name"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("gh_repo:owner_type_invented", "gh.repo.v1",
        rewrite(repo, b'"type":"User"', b'"type":"Robot"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)

    env = load_normalized("env_one.json")
    add("gh_env:truncated", "gh.environment.v1", truncate(env), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("gh_env:duplicate_key", "gh.environment.v1",
        duplicate_key(env, b'"can_admins_bypass"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("gh_env:unknown_protection_field", "gh.environment.v1",
        rewrite(env, b'"can_admins_bypass":true',
                b'"can_admins_bypass":true,"new_protection_thing":true'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    secrets = load_normalized("env_secrets.json")
    add("gh_secrets:count_disagrees", "gh.environment.secrets.v1",
        rewrite(secrets, b'"total_count":0', b'"total_count":3'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("gh_secrets:truncated", "gh.environment.secrets.v1", truncate(secrets),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # ===================================================================================
    # the 2026-08-05 captures
    # ===================================================================================

    # --- the OIDC claim set -------------------------------------------------------------
    claims = load_normalized("oidc_claims.json")
    add("oidc:truncated", "oidc.github.claims.v1", truncate(claims),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:duplicate_key", "oidc.github.claims.v1", duplicate_key(claims, b'"repository"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:wrong_issuer", "oidc.github.claims.v1",
        rewrite(claims, b'"https://token.actions.githubusercontent.com"',
                b'"https://token.actions.githubusercontent.example"'),
        R.AUT_IDENTITY_NOT_PERMITTED)
    add("oidc:missing_claim", "oidc.github.claims.v1",
        rewrite(claims, b'"runner_environment"', b'"runner_enviroment"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:exp_before_iat", "oidc.github.claims.v1",
        rewrite(claims, b'"exp": 1785949597', b'"exp": 1785949000'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:nbf_after_exp", "oidc.github.claims.v1",
        rewrite(claims, b'"nbf": 1785948997', b'"nbf": 1785959997'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:non_integer_exp", "oidc.github.claims.v1",
        rewrite(claims, b'"exp": 1785949597', b'"exp": "1785949597"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("oidc:visibility_invented", "oidc.github.claims.v1",
        rewrite(claims, b'"repository_visibility": "public"',
                b'"repository_visibility": "translucent"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- the keyless bundle ---------------------------------------------------------------
    keyless = load_normalized("cosign_keyless_bundle.json")
    add("keyless:truncated", "cosign.bundle.keyless.legacy.v1", truncate(keyless),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("keyless:duplicate_key", "cosign.bundle.keyless.legacy.v1",
        duplicate_key(keyless, b'"base64Signature"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("keyless:signature_byte_flipped", "cosign.bundle.keyless.legacy.v1",
        flip_signature_byte(keyless, b'"base64Signature":'), R.AUT_SIGNATURE_INVALID)
    add("keyless:cert_byte_flipped", "cosign.bundle.keyless.legacy.v1",
        flip_signature_byte(keyless, b'"cert":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    # A byte flipped in the base64 body decodes to a DIFFERENT but still-parseable JSON
    # envelope ("apiVersion" -> "alVersion"). The legacy bundle has no inclusion proof, so
    # nothing binds the body bytes; the envelope check is what catches this.
    add("keyless:logged_body_byte_flipped", "cosign.bundle.keyless.legacy.v1",
        flip_signature_byte(keyless, b'"body":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("keyless:logged_signature_swapped", "cosign.bundle.keyless.legacy.v1",
        _rewrite_logged(keyless, "signature", "content",
                        "MEQCIBGS8MCPhnhQ38TjXhOme037+uW/XDjK9wV2Wdd2lghaAiAb3HiK8lAyMgBUas"
                        "ESaFbdagBSbptn60Mce4hzM0FKYQ=="[:-3] + "AAA="),
        R.AUT_SIGNATURE_INVALID)
    add("keyless:logged_cert_swapped", "cosign.bundle.keyless.legacy.v1",
        _rewrite_logged(keyless, "signature", "publicKey",
                        {"content": "U1lOVEhFVElDLUFEVkVSU0FSSUFM"}),
        R.AUT_SIGNATURE_INVALID)
    add("keyless:set_not_der", "cosign.bundle.keyless.legacy.v1",
        rewrite(keyless, b'"SignedEntryTimestamp":"ME', b'"SignedEntryTimestamp":"MU'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("keyless:integrated_time_outside_cert_validity",
        "cosign.bundle.keyless.legacy.v1",
        rewrite(keyless, b'"integratedTime":1785949299', b'"integratedTime":1785949999'),
        R.AUT_BINDING_MISMATCH)
    add("keyless:bad_log_id", "cosign.bundle.keyless.legacy.v1",
        rewrite(keyless, b'"logID":"c0d23d6a', b'"logID":"zzd23d6a'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("keyless:unknown_field", "cosign.bundle.keyless.legacy.v1",
        rewrite(keyless, b'{"base64Signature"', b'{"newThing":1,"base64Signature"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- the protected environment ---------------------------------------------------------
    protected = load_normalized("env_protected_one.json")
    add("env_protected:truncated", "gh.environment.protected.v1", truncate(protected),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("env_protected:duplicate_key", "gh.environment.protected.v1",
        duplicate_key(protected, b'"can_admins_bypass"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("env_protected:unknown_rule_field", "gh.environment.protected.v1",
        rewrite(protected, b'"prevent_self_review":false',
                b'"prevent_self_review":false,"bypass_everything":true'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("env_protected:unknown_rule_type", "gh.environment.protected.v1",
        rewrite(protected, b'"type":"required_reviewers"', b'"type":"vibes_check"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    protected_list = load_normalized("env_protected_list.json")
    add("env_protected_list:truncated", "gh.environment.list.v1", truncate(protected_list),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("env_protected_list:count_disagrees", "gh.environment.list.v1",
        rewrite(protected_list, b'"total_count":1', b'"total_count":2'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # ===================================================================================
    # the 2026-08-06 v0.3 round — cosign v3.1.3, live against public Sigstore
    # ===================================================================================

    # --- the v0.3 KEYED bundle -----------------------------------------------------------
    v03 = load_normalized("bundle_v03.json")
    S03 = "cosign.bundle.v0_3.keyed"
    add("v03_bundle:truncated", S03, truncate(v03), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:duplicate_key", S03, duplicate_key(v03, b'"mediaType"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:duplicate_log_index", S03,
        duplicate_key(v03, b'"logIndex"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:signature_byte_flipped", S03,
        flip_signature_byte(v03, b'"signature":'), R.AUT_SIGNATURE_INVALID)
    add("v03_bundle:message_digest_byte_flipped", S03,
        flip_signature_byte(v03, b'"digest":'), R.AUT_BINDING_MISMATCH)
    # The body IS the Merkle leaf, so any byte change moves the recomputed root. The envelope
    # check happens to catch this particular flip first (it renames a key); either way it is
    # refused, and bundle:proof_hash_flipped below exercises the proof itself.
    add("v03_bundle:tlog_body_byte_flipped", S03,
        flip_signature_byte(v03, b'"canonicalizedBody":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:logged_digest_swapped", S03,
        _rewrite_keyed_body(v03, ("data", "hash", "value"), "c" * 64), R.AUT_BINDING_MISMATCH)
    add("v03_bundle:proof_hash_flipped", S03,
        flip_byte(v03, b'"4eoqltAL6NIRDkssFG/CLn4TeF8u7Pzv+irdKxhVaDw="', 2),
        R.AUT_SIGNATURE_INVALID)
    add("v03_bundle:root_hash_swapped", S03,
        rewrite(v03, b'"rootHash":"Nq/Fga/8OWJTeIawHJ66MCJwhRKcOlfFTEWxCgTjU98="',
                b'"rootHash":"AAAAga/8OWJTeIawHJ66MCJwhRKcOlfFTEWxCgTjU98="'),
        R.AUT_SIGNATURE_INVALID)
    add("v03_bundle:tree_size_swapped", S03,
        rewrite(v03, b'"treeSize":"2232883522"', b'"treeSize":"2232883521"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:media_type_v0_2", S03,
        rewrite(v03, b"bundle.v0.3+json", b"bundle.v0.2+json"), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:no_verification_material", S03,
        rewrite(v03, b'"verificationMaterial":', b'"verificationMaterialX":'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:key_hint_swapped", S03,
        rewrite(v03, b'"hint":"vc9TQdmzUJ/mNjyHYT9bExk9sDxQ6lwxpv3FuiyyO9U="',
                b'"hint":"AAAATQdmzUJ/mNjyHYT9bExk9sDxQ6lwxpv3FuiyyO9U="'),
        R.AUT_SIGNATURE_INVALID)
    add("v03_bundle:checkpoint_size_swapped", S03,
        rewrite(v03, b"1193050959916656506\\n2232883522\\n",
                b"1193050959916656506\\n2232883523\\n"),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_bundle:log_id_swapped", S03,
        rewrite(v03, b'"keyId":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="',
                b'"keyId":"AAAAatQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    # Turn the KEYED capture into a KEYLESS-shaped one. The shape is recognised and refused,
    # because the v0.3 keyless serialisation has never been captured — bundle_v03.json did NOT
    # unblock it. See captures/normalized/keyless_attempt.txt.
    add("v03_bundle:keyless_shape_still_blocked", "cosign.bundle.keyless.v0_3",
        rewrite(v03, b'"publicKey":{"hint"',
                b'"certificate":{"rawBytes":"MIIB"},"publicKey":{"hint"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- the cosign v3.1.3 version block ---------------------------------------------------
    v313 = load_normalized("cosign_version_3_1_3.json")
    add("v313_version:truncated", "cosign.version.v1", truncate(v313),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v313_version:duplicate_key", "cosign.version.v1",
        duplicate_key(v313, b'"gitVersion"'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v313_version:unsupported_new", "cosign.version.v1",
        rewrite(v313, b'"v3.1.3"', b'"v4.1.3"'), R.AUT_TOOL_VERSION_UNSUPPORTED)
    add("v313_version:dirty_tree", "cosign.version.v1",
        rewrite(v313, b'"clean"', b'"dirty"'), R.AUT_TOOL_VERSION_UNSUPPORTED)

    # --- the two v3.1.3 verify-blob texts ---------------------------------------------------
    ok_v03 = load_normalized("verify_v03_ok.txt")
    add("v03_verify_ok:text_drifted", "cosign.verifyblob.v03.ok.v1",
        rewrite(ok_v03, b"Verified OK", b"Verified ok"), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_verify_ok:truncated", "cosign.verifyblob.v03.ok.v1", truncate(ok_v03),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_verify_ok:extra_line", "cosign.verifyblob.v03.ok.v1",
        ok_v03 + b"\nand the certificate is fine too\n", R.AUT_OUTPUT_SHAPE_UNKNOWN)
    fail_v03 = load_normalized("verify_v03_fail.txt")
    add("v03_verify_fail:text_drifted", "cosign.verifyblob.v03.fail.v1",
        rewrite(fail_v03, b"invalid signature", b"invalid signatur"),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("v03_verify_fail:truncated", "cosign.verifyblob.v03.fail.v1", truncate(fail_v03),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- the FRESH Rekor REST entry ----------------------------------------------------------
    fresh = load_normalized("rekor_rest_entry_fresh.json")
    SFR = "rekor.rest.entry.fresh.v1"
    add("fresh_rest:truncated", SFR, truncate(fresh), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:duplicate_key", SFR, duplicate_key(fresh, b'"integratedTime"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:duplicate_log_index", SFR, duplicate_key(fresh, b'"logIndex"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:body_byte_flipped", SFR, flip_signature_byte(fresh, b'"body":'),
        R.AUT_BINDING_MISMATCH)
    add("fresh_rest:proof_hash_flipped", SFR,
        rewrite(fresh, b'"98a737a9a61dc3c56c97b383284ca01c12695e50aed494e08aaee8814adcc6f5"',
                b'"98a737a9a61dc3c56c97b383284ca01c12695e50aed494e08aaee8814adcc6f4"'),
        R.AUT_SIGNATURE_INVALID)
    add("fresh_rest:root_hash_swapped", SFR,
        rewrite(fresh,
                b'"rootHash":"f2a13ca0054fbf4bd4aae3fc9498d6596d6302ef0b7107fb60e6269e8d33388d"',
                b'"rootHash":"f2a13ca0054fbf4bd4aae3fc9498d6596d6302ef0b7107fb60e6269e8d33388e"'),
        R.AUT_SIGNATURE_INVALID)
    add("fresh_rest:tree_size_swapped", SFR,
        rewrite(fresh, b'"treeSize":2232891025', b'"treeSize":2232891024'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:log_id_swapped", SFR,
        rewrite(fresh, b'"logID":"c0d23d6a', b'"logID":"c0d23d6b'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:no_verification_block", SFR,
        rewrite(fresh, b'"verification":', b'"verificationX":'), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:set_not_der", SFR,
        rewrite(fresh, b'"signedEntryTimestamp":"MEUCIF', b'"signedEntryTimestamp":"MUUCIF'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    # The shard-local proof index may never exceed the entry's GLOBAL index. This is the
    # replacement for the old proof.logIndex == entry.logIndex equality, which the sharded log
    # disproved (see rekor.parse_rest_entry).
    add("fresh_rest:shard_index_ahead_of_global", SFR,
        rewrite(fresh, b'"logIndex":2232883438', b'"logIndex":2354787701'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_rest:shard_index_outside_its_own_tree", SFR,
        rewrite(fresh, b'"logIndex":2232883438,"rootHash"',
                b'"logIndex":2232891025,"rootHash"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    # --- the FRESH REST loginfo (the shard map) ------------------------------------------
    linfo = load_normalized("rekor_loginfo_fresh.json")
    SLI = "rekor.rest.loginfo.v1"
    add("fresh_loginfo:truncated", SLI, truncate(linfo), R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_loginfo:duplicate_key", SLI, duplicate_key(linfo, b'"treeSize"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_loginfo:root_hash_swapped", SLI,
        rewrite(linfo,
                b'"rootHash":"82deb4bc7d02cab74a6fb53a5b642930cea4e74fdf3d5eae6cb654fa3b4b19bd"',
                b'"rootHash":"82deb4bc7d02cab74a6fb53a5b642930cea4e74fdf3d5eae6cb654fa3b4b19be"'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_loginfo:tree_size_swapped", SLI,
        rewrite(linfo, b'"treeSize":2232891295', b'"treeSize":2232891296'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)
    add("fresh_loginfo:shard_size_swapped", SLI,
        rewrite(linfo, b'"treeSize":4163431', b'"treeSize":4163432'),
        R.AUT_OUTPUT_SHAPE_UNKNOWN)

    return cases


# ---------------------------------------------------------------------------------------
# CROSS-SOURCE mutations — two documents that must agree, made to disagree
# ---------------------------------------------------------------------------------------


def cross_source_rejections() -> List[Dict[str, object]]:
    """[{label, kind, data..., expect}] for checks that need MORE THAN ONE document.

    These cannot live in `rejections()`, which routes one blob to one parser. Every case here
    parses fine on its own — that is the point. What is being tested is that two independently
    valid documents which describe the same log entry DIFFERENTLY produce a refusal rather than
    a merge, and that freshness is judged against the clock rather than assumed.
    """
    cases = []

    def add(label, kind, expect, **kw):
        cases.append(dict(kw, label=label, kind=kind, expect=expect))

    fresh = load_normalized("rekor_rest_entry_fresh.json")
    v03 = load_normalized("bundle_v03.json")
    linfo = load_normalized("rekor_loginfo_fresh.json")

    # --- bundle vs REST entry -------------------------------------------------------------
    # Only the GLOBAL logIndex is moved. The shard-local proof index is left alone on purpose,
    # so the Merkle proof still verifies and the entry still parses cleanly — the document is
    # internally consistent and only disagrees with the OTHER document. Moving the proof index
    # instead would break the proof, and the entry would be refused before the cross-check ever
    # ran, which would test the wrong thing.
    add("cross:logIndex_mismatch_bundle_vs_rest", "tlog_agreement", R.AUT_BINDING_MISMATCH,
        bundle=v03, entry=rewrite(fresh, b'"logIndex":2354787700', b'"logIndex":2354787699'),
        why="the REST entry names a different global logIndex than the bundle's tlog entry")
    add("cross:integratedTime_mismatch_bundle_vs_rest", "tlog_agreement",
        R.AUT_BINDING_MISMATCH, bundle=v03,
        entry=rewrite(fresh, b'"integratedTime":1785990048', b'"integratedTime":1785990049'),
        why="the log and the bundle disagree about when the entry was integrated")
    add("cross:stale_2021_entry_paired_with_fresh_bundle", "tlog_agreement",
        R.AUT_BINDING_MISMATCH, bundle=v03, entry=load_normalized("rekor_rest_entry.json"),
        why="the 2021 negative fixture is not this bundle's entry, and pairing them must "
            "refuse rather than quietly supply freshness from an unrelated record")

    # --- entry vs the shard map -------------------------------------------------------------
    # Both documents stay internally consistent — one whole sealed shard is removed from the
    # map, each remaining signed tree head still matching its own root and size. Editing a
    # shard's treeSize in place would instead break that shard's signed tree head and be
    # refused by parse_rest_loginfo before the arithmetic ran.
    add("cross:shard_offset_disagrees_with_loginfo", "shard_offset", R.AUT_BINDING_MISMATCH,
        entry=fresh, loginfo=_drop_inactive_shard(linfo),
        why="with one sealed shard missing from the map, global minus shard-local no longer "
            "equals the inactive shards' total")
    add("cross:entry_global_index_moved_off_the_shard_map", "shard_offset",
        R.AUT_BINDING_MISMATCH,
        entry=rewrite(fresh, b'"logIndex":2354787700', b'"logIndex":2354787800'), loginfo=linfo,
        why="the entry claims a global position 100 further along than its shard-local proof "
            "and the shard map together allow")
    add("cross:2021_entry_against_the_ACTIVE_shard_map", "shard_offset",
        R.AUT_BINDING_MISMATCH, entry=load_normalized("rekor_rest_entry.json"), loginfo=linfo,
        why="the 2021 entry's proof is against a RETIRED shard (tree 3904496407287907110); a "
            "proof against a sealed shard says nothing about the live log")

    # --- freshness ----------------------------------------------------------------------------
    add("cross:fresh_entry_just_outside_the_window", "freshness", R.AUT_FRESHNESS_EXPIRED,
        entry=fresh, now=FRESH_INTEGRATED_AT + 3601, max_age=3600,
        why="one second past the 3600s default is expired; the boundary is a boundary")
    add("cross:fresh_entry_a_day_later", "freshness", R.AUT_FRESHNESS_EXPIRED,
        entry=fresh, now=FRESH_INTEGRATED_AT + 86400, max_age=3600,
        why="the whole point of a freshness window")
    add("cross:fresh_entry_forward_dated", "freshness", R.AUT_FRESHNESS_EXPIRED,
        entry=fresh, now=FRESH_INTEGRATED_AT - 1, max_age=3600,
        why="an entry dated in the future is a broken log or a forged record, never fresh")
    add("cross:2021_entry_is_the_permanent_negative", "freshness", R.AUT_FRESHNESS_EXPIRED,
        entry=load_normalized("rekor_rest_entry.json"), now=FRESH_INTEGRATED_AT, max_age=3600,
        why="logIndex 1000000 was integrated in 2021 and can never be fresh again")

    return cases


def _drop_inactive_shard(data: bytes, index: int = 0) -> bytes:
    """Remove one sealed shard from a REST loginfo map, leaving every remaining shard's own
    signed tree head intact. The document stays internally valid; only the shard-offset
    arithmetic against a real entry breaks, which is the thing under test."""
    import json as _json
    doc = _json.loads(data.decode("utf-8"))
    shards = doc.get("inactiveShards") or []
    if not shards:
        raise FixtureError("cannot drop a shard: the loginfo lists none")
    del shards[index]
    return _json.dumps(doc).encode("utf-8")


def _rewrite_keyed_body(data: bytes, path, value):
    """Re-encode a v0.3 bundle with one field of its logged `canonicalizedBody` replaced."""
    import json as _json
    doc = _json.loads(data.decode("utf-8"))
    entry = doc["verificationMaterial"]["tlogEntries"][0]
    body = _json.loads(base64.b64decode(entry["canonicalizedBody"]))
    target = body["spec"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    entry["canonicalizedBody"] = base64.b64encode(
        _json.dumps(body, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return _json.dumps(doc).encode("utf-8")


def _rewrite_logged(data: bytes, section: str, key: str, value):
    """Re-encode a legacy bundle with one field of its LOGGED body replaced.

    Used to decouple the bundle's own signature/certificate from the copies inside the
    transparency-log entry — the cross-check that proves neither can be swapped alone.
    """
    import json as _json
    doc = _json.loads(data.decode("utf-8"))
    body = _json.loads(base64.b64decode(doc["rekorBundle"]["Payload"]["body"]))
    body["spec"][section][key] = value
    doc["rekorBundle"]["Payload"]["body"] = base64.b64encode(
        _json.dumps(body, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return _json.dumps(doc).encode("utf-8")


def qualification_cases():
    """Environment records for the QUALIFYING predicate, with the answer each must produce.

    These are policy cases, not shape cases: every record here parses. What is being tested
    is `gh.is_qualifying_environment`, and the fixture that is expected to QUALIFY is derived
    from the real protected capture by fixing exactly the three flags that disqualify it —
    which is also the shortest possible statement of what an adopter has to change.
    """
    from ..models import reasons as R_

    real = load_normalized("env_protected_one.json")
    empty = load_normalized("env_one.json")

    def fixed(data, **swaps):
        for old, new in swaps.items():
            data = rewrite(data, old.encode(), new.encode())
        return data

    qualifying = fixed(
        real,
        **{'"prevent_self_review":false': '"prevent_self_review":true',
           '"can_admins_bypass":true': '"can_admins_bypass":false',
           '"deployment_branch_policy":null':
               '"deployment_branch_policy":{"protected_branches":true,'
               '"custom_branch_policies":false}'})

    # Empty the reviewers array properly (via JSON) so the record stays SHAPE-valid and the
    # only thing wrong with it is the policy question: a rule that names nobody.
    import json as _json
    stripped = _json.loads(qualifying.decode("utf-8"))
    for rule in stripped["protection_rules"]:
        if rule.get("type") == "required_reviewers":
            rule["reviewers"] = []
    no_reviewers = _json.dumps(stripped).encode("utf-8")

    return [
        {"label": "real capture: rules that do not bind the builder",
         "data": real, "qualifies": False, "expect": R_.AUT_PRINCIPAL_NOT_DISTINCT},
        {"label": "real capture: no rules at all",
         "data": empty, "qualifies": False, "expect": R_.AUT_PRINCIPAL_NOT_DISTINCT},
        {"label": "DERIVED-FROM-CAPTURE: the three flags fixed -> qualifies",
         "data": qualifying, "qualifies": True, "expect": None},
        {"label": "DERIVED-FROM-CAPTURE: reviewers list emptied -> approves itself",
         "data": no_reviewers, "qualifies": False,
         "expect": R_.AUT_PRINCIPAL_NOT_DISTINCT},
    ]


# ---------------------------------------------------------------------------------------
# an evidence set built from the real captures, for adapter-level tests
# ---------------------------------------------------------------------------------------


def bundle_message_digest_hex() -> str:
    """The digest the captured bundle actually signs. A decision with THIS digest would bind;
    every other decision must produce AUT_BINDING_MISMATCH."""
    import json
    doc = json.loads(load_text("cosign_signblob_bundle.json"))
    return base64.b64decode(doc["messageSignature"]["messageDigest"]["digest"]).hex()


def keyless_message_digest_hex() -> str:
    """The digest the captured KEYLESS bundle signs. A decision with this digest binds."""
    import json
    doc = json.loads(load_text("cosign_keyless_bundle.json"))
    body = json.loads(base64.b64decode(doc["rekorBundle"]["Payload"]["body"]))
    return body["spec"]["data"]["hash"]["value"]


def keyless_config(directory=None, mode="ci", freshness_max_age_seconds=None):
    """An evidence set built on the KEYLESS bundle and the real OIDC claim set.

    This is the configuration that exercises the identity path end to end. It still refuses,
    for one reason and one reason only: the capture's JSON was sanitized to OWNER/REPO while
    the certificate's signed DER says `samerzakaria/shipgate-shape-capture`, so the identity
    check correctly disagrees. See SHAPES.json bindingValidated:false.
    """
    cfg = evidence_config(directory=directory, mode=mode,
                          freshness_max_age_seconds=freshness_max_age_seconds)
    cfg["cosign"]["bundle"] = "cosign_keyless_bundle.json"
    cfg["oidc"] = {"claims": "oidc_claims.json",
                   "expectedIssuer": "https://token.actions.githubusercontent.com",
                   "expectedAudience": "sigstore"}
    cfg["gh"]["environment"] = "env_protected_one.json"
    cfg["gh"]["environmentList"] = "env_protected_list.json"
    return cfg


def fresh_bundle_message_digest_hex() -> str:
    """The digest bundle_v03.json signs — sha256("ship-gate v4.0 capture blob")."""
    import json
    doc = json.loads(load_text("bundle_v03.json"))
    return base64.b64decode(doc["messageSignature"]["messageDigest"]["digest"]).hex()


def fresh_evidence_config(directory=None, mode="ci", freshness_max_age_seconds=None):
    """The 2026-08-06 evidence set: the v0.3 bundle and the REST entry BOUND to it.

    This is the first configuration in which `rekor.restEntry` describes the same log entry as
    `cosign.bundle`, so the cross-source agreement check has two real sources to compare and
    the shard-offset check has a real shard map. It still cannot reach CI_ATTESTED, for one
    reason that no amount of freshness fixes: the bundle is KEYED. It proves possession of a
    key, and a key is not an identity — there is no certificate in it to name anybody.
    """
    directory = directory or normalized_dir()
    cfg = {
        "schema": "shipgate.authority.config/1",
        "mode": mode,
        "evidenceDir": directory,
        "cosign": {
            "versionJson": "cosign_version_3_1_3.json",
            "bundle": "bundle_v03.json",
            "verifyStdout": "verify_v03_ok.txt",
            "verifyExitCode": 0,
        },
        "rekor": {
            "restEntry": "rekor_rest_entry_fresh.json",
            "restLogInfo": "rekor_loginfo_fresh.json",
        },
        "gh": {
            "version": "2.65.0",
            "repo": "repo.json",
            "environment": "env_one.json",
            "environmentSecrets": "env_secrets.json",
            "environmentName": "verifier",
        },
    }
    if freshness_max_age_seconds is not None:
        cfg["freshnessMaxAgeSeconds"] = freshness_max_age_seconds
    return cfg


def evidence_config(directory=None, mode="ci", freshness_max_age_seconds=None):
    """A config dict pointing at the REAL captures, for exercising the adapters end to end.

    The freshness window defaults to something enormous ONLY because the captured Rekor entry
    is from 2021 — that is a property of the corpus, not a suggestion. Real deployments use
    the 3600s default; `contracts` caps the configurable value at 7 days.
    """
    directory = directory or normalized_dir()
    cfg = {
        "schema": "shipgate.authority.config/1",
        "mode": mode,
        "evidenceDir": directory,
        "cosign": {
            "versionJson": "cosign_version.json",
            "bundle": "cosign_signblob_bundle.json",
            "verifyStdout": "cosign_verify_ok.txt",
            "verifyExitCode": 0,
        },
        "rekor": {
            "version": "1.5.3",
            "restEntry": "rekor_rest_entry.json",
            "cliGet": "rekor_get_logindex.json",
            "cliLogInfo": "rekor_loginfo.json",
        },
        "gh": {
            "version": "2.65.0",
            "repo": "repo.json",
            "environment": "env_one.json",
            "environmentSecrets": "env_secrets.json",
            "environmentName": "verifier",
        },
    }
    if freshness_max_age_seconds is not None:
        cfg["freshnessMaxAgeSeconds"] = freshness_max_age_seconds
    return cfg


__all__ = [
    "CAPTURE_FILES", "DOC_FILES", "FixtureError", "NORMALIZED_DIR", "RAW_DIR",
    "CERT_REPOSITORY", "FRESH_INTEGRATED_AT", "FRESH_LOG_INDEX", "FRESH_PROOF_LOG_INDEX",
    "FRESH_SHARD_OFFSET", "KEYLESS_ATTEMPT_FILE", "KEYLESS_ATTEMPT_MARKER",
    "KEYLESS_SIGNED_AT", "SANITIZED_CAPTURES", "SYNTHETIC_PREFIX",
    "TESTS_DATA_DIR", "UTF8_BOM_RAW_FILES", "UTF16_RAW_FILES", "bundle_message_digest_hex",
    "cross_source_rejections", "duplicate_key", "evidence_config", "flip_byte",
    "flip_signature_byte", "fresh_bundle_message_digest_hex", "fresh_evidence_config",
    "keyless_config", "keyless_message_digest_hex", "load_normalized", "load_raw", "load_text",
    "normalized_path", "positives", "qualification_cases", "raw_path", "rejections",
    "rewrite", "synthetic", "synthetic_names", "truncate",
]
