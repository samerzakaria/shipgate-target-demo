"""Extract an externally verified timestamp from GitHub attestation output."""
import argparse
import pathlib

from .parsers import ghattest


class ExternalTimeError(ValueError):
    """The supplied verifier output cannot establish an external timestamp."""


def extract_github_attestation_time(verify_output, gh_version_output):
    """Return the conservative (oldest) verified transparency timestamp.

    The input is accepted only after the existing digest-pinned GitHub output parser and
    version gate accept it. No local clock participates in choosing the timestamp.
    """
    version = ghattest.parse_version(gh_version_output)
    if not version.ok:
        raise ExternalTimeError(version.detail)
    parsed = ghattest.parse_verify_output(
        verify_output, gh_version=version.data["version"])
    if not parsed.ok:
        raise ExternalTimeError(parsed.detail)
    stamps = parsed.data.get("verifiedTimestamps") or []
    if not stamps:
        raise ExternalTimeError(
            "GitHub reported no verified transparency timestamp")
    epochs = [item.get("epoch") for item in stamps]
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0
           for value in epochs):
        raise ExternalTimeError("GitHub returned an invalid verified timestamp")
    return min(epochs)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="extract GitHub's verified external attestation timestamp")
    parser.add_argument("--verify-output", required=True)
    parser.add_argument("--gh-version", required=True)
    args = parser.parse_args(argv)
    try:
        epoch = extract_github_attestation_time(
            pathlib.Path(args.verify_output).read_bytes(),
            pathlib.Path(args.gh_version).read_bytes())
    except (OSError, ExternalTimeError) as exc:
        parser.error(str(exc))
    print(epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
