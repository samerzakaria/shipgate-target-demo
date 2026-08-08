"""Fail-closed binding of verifier dispatch claims to downloaded candidate bytes."""
import argparse
import hashlib
import pathlib
import re

from ..util.canonical import digest_of, loads_strict


class CandidateBindingError(ValueError):
    """The requested, enveloped, or observed candidate digests disagree."""


def _claimed_digest(raw, allowed, name):
    value = str(raw).strip().lower()
    if ":" in value:
        algorithm, value = value.split(":", 1)
    else:
        algorithm = "sha512" if len(value) == 128 else "sha256"
    if algorithm not in allowed or not re.fullmatch(r"[0-9a-f]+", value):
        raise CandidateBindingError(
            f"{name} is not a supported hexadecimal digest")
    expected_length = hashlib.new(algorithm).digest_size * 2
    if len(value) != expected_length:
        raise CandidateBindingError(
            f"{name} has {len(value)} hex characters; {algorithm} needs "
            f"{expected_length}")
    return algorithm, value


def verify_candidate(decision_path, artifact_path, expected_decision_digest,
                     expected_artifact_digest):
    """Return the verified digests, or raise CandidateBindingError.

    Dispatch inputs are never trusted as evidence. They must agree with the canonical
    decision body, its envelope, its subject, and the downloaded artifact bytes.
    """
    decision_path = pathlib.Path(decision_path)
    artifact_path = pathlib.Path(artifact_path)
    try:
        envelope = loads_strict(decision_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CandidateBindingError(f"unreadable decision envelope: {exc}") from exc
    if not isinstance(envelope, dict) or set(("decision", "decisionDigest")) - set(envelope):
        raise CandidateBindingError("candidate decision is not a decision envelope")
    if not isinstance(envelope["decision"], dict):
        raise CandidateBindingError("decision envelope body is not an object")

    actual_decision = digest_of(envelope["decision"])
    envelope_decision = str(envelope["decisionDigest"]).lower()
    _algorithm, requested_decision = _claimed_digest(
        expected_decision_digest, {"sha256"}, "expected decision digest")
    if not (actual_decision == envelope_decision == requested_decision):
        raise CandidateBindingError(
            "decision digest binding failed: requested, envelope and canonical "
            "decision bytes do not agree")

    artifact_algorithm, requested_artifact = _claimed_digest(
        expected_artifact_digest, {"sha256", "sha512"}, "expected artifact digest")
    try:
        actual_artifact = hashlib.new(
            artifact_algorithm, artifact_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CandidateBindingError(f"unreadable candidate artifact: {exc}") from exc
    subject = envelope["decision"].get("subject")
    subject_artifact = str(
        subject.get("artifactDigest", "") if isinstance(subject, dict) else "").lower()
    if not subject_artifact:
        raise CandidateBindingError("decision subject has no artifactDigest")
    if not (actual_artifact == subject_artifact == requested_artifact):
        raise CandidateBindingError(
            "artifact digest binding failed: requested, decision and downloaded "
            "artifact bytes do not agree")
    return {"decisionDigest": actual_decision,
            "artifactDigest": actual_artifact,
            "artifactDigestAlgorithm": artifact_algorithm}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="bind verifier dispatch digests to downloaded candidate bytes")
    parser.add_argument("--decision", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--expected-decision-digest", required=True)
    parser.add_argument("--expected-artifact-digest", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_candidate(
            args.decision, args.artifact, args.expected_decision_digest,
            args.expected_artifact_digest)
    except CandidateBindingError as exc:
        parser.error(str(exc))
    print("candidate digest bindings verified: "
          f"decision={result['decisionDigest']} "
          f"artifact={result['artifactDigestAlgorithm']}:{result['artifactDigest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
