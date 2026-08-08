"""Run `gh attestation verify`, rather than reading a file that claims gh ran.

WHAT THIS MODULE IS. The GitHub artifact-attestation adapter's execution half. GitHub ships
its own verifier for its own attestations — certificate chain to the Sigstore/GitHub trust
roots, SCT, tlog proof, artifact digest against the in-toto subject — and this kit does NOT
reimplement any of that cryptography. It runs the installed `gh` CLI and judges the REAL
subprocess result. The parsing half (shape-gated, fail-closed) is `parsers/ghattest.py`.

THE RULES, all inherited from the cosign precedent and enforced here:

  * The spawn goes through `toolexec.run`: no shell, pinned binary, allowlisted environment,
    bounded time, bounded and truncation-marked output, the RESOLVED executable recorded.
  * There is NO parameter for a captured stdout, a captured exit code, or an expected
    verdict. The only verdict is the exit code of the process this module just ran.
  * Identity constraints passed to gh come from the DECISION SUBJECT and the caller's
    verifier-side configuration — never from the repository under judgement. The one
    identity flag this module sets is `--repo <subject>`; there is deliberately no
    parameter for `--cert-identity-regex`, because a repository-supplied regex constraint
    is how an operator widens a check while appearing to narrow one.
  * OFFLINE FIRST. With a bundle and a trusted root on disk, gh verifies fully offline —
    no API call, no token. Live mode (fetching attestations from the GitHub API) needs a
    token and is subject to this kit's usual rule: a credential is fine, an ANSWER is not.

VERSION GATE. `gh attestation verify` with `--format json` is validated against gh v2.97.0;
the supported range is pinned in `parsers/ghattest.py` beside the shape that depends on it.
An unidentified or out-of-range gh is refused, exactly as an unidentified cosign is.
"""
import os
import re
from typing import Any, Dict, Optional

from . import toolexec

DEFAULT_BINARY = "gh"
TIMEOUT_SECONDS = 120

#: First line of `gh --version`, e.g. `gh version 2.97.0 (2026-07-31)`.
_VERSION_LINE = re.compile(r"^gh version (\d+\.\d+\.\d+)")


class GhExecError(Exception):
    """gh could not be run, or produced something unusable."""


class Blocked(GhExecError):
    """gh is not available here. BLOCKED — never a fallback to a replayed verdict."""


def binary(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the gh binary from an explicit path, the environment, or PATH."""
    return toolexec.resolve_binary(DEFAULT_BINARY, "SHIPGATE_GH_BINARY", explicit)


def available(explicit: Optional[str] = None):
    """(usable, detail). Never raises, so `doctor` can report it without running anything."""
    found = binary(explicit)
    if not found:
        return False, ("gh is not on this verifier's PATH and SHIPGATE_GH_BINARY is unset, "
                       "so no GitHub artifact attestation can be checked by the tool that "
                       "knows how. The verdict is BLOCKED, not read from a file.")
    try:
        version = run_version(found)
    except GhExecError as exc:
        return False, str(exc)
    return True, f"gh {version} at {found}"


def run_version(explicit: Optional[str] = None) -> str:
    """The REAL `gh --version` first line, parsed. Raises rather than guessing."""
    found = binary(explicit)
    if not found:
        raise Blocked(available(explicit)[1])
    try:
        result = toolexec.run([found, "--version"], timeout_seconds=TIMEOUT_SECONDS,
                              extra_env={"TZ": "UTC"}, tool_name="gh")
    except toolexec.ToolBlocked as exc:
        raise Blocked(str(exc))
    except toolexec.ToolExecError as exc:
        raise GhExecError(str(exc))
    if result["exitCode"] != 0:
        raise GhExecError(f"`gh --version` exited {result['exitCode']}: "
                          f"{result['stderr'][:200]}")
    match = _VERSION_LINE.match(result["stdout"].strip())
    if not match:
        raise GhExecError(f"`gh --version` output was not recognised: "
                          f"{result['stdout'][:120]!r}")
    return match.group(1)


def verify_attestation(artifact_path: str, *, repository: str,
                       bundle_path: Optional[str] = None,
                       trusted_root_path: Optional[str] = None,
                       digest_alg: str = "sha256",
                       predicate_type: Optional[str] = None,
                       signer_workflow: Optional[str] = None,
                       deny_self_hosted: bool = True,
                       explicit_binary: Optional[str] = None) -> Dict[str, Any]:
    """Actually run `gh attestation verify`. Returns the REAL exit code and output.

    `repository` is REQUIRED and must be the decision's subject — gh enforces that the
    attestation's certificate belongs to that repository, which is the identity constraint
    that makes the verification mean something. Running without one would verify that
    SOMEBODY attested SOMETHING, which is not a fact worth recording (the cosign rule).

    With `bundle_path` and `trusted_root_path` the verification is fully offline. Without a
    bundle, gh fetches attestations from the GitHub API, which requires network and a token
    on the verifier's own environment (GH_TOKEN) — a credential, never an answer.
    """
    found = binary(explicit_binary)
    if not found:
        raise Blocked(available(explicit_binary)[1])
    if not os.path.isfile(artifact_path):
        raise GhExecError(f"nothing to verify: {artifact_path} does not exist")
    if not repository or "/" not in repository:
        raise GhExecError(f"{repository!r} is not an owner/repo pair; the identity "
                          "constraint must name the decision's subject repository")
    if digest_alg not in ("sha256", "sha512"):
        raise GhExecError(f"unsupported digest algorithm {digest_alg!r}; gh supports "
                          "sha256 and sha512")
    if bundle_path and not os.path.isfile(bundle_path):
        raise GhExecError(f"no attestation bundle at {bundle_path}")
    if trusted_root_path and not os.path.isfile(trusted_root_path):
        raise GhExecError(f"no trusted root at {trusted_root_path}")

    argv = [found, "attestation", "verify", artifact_path,
            "--repo", repository, "--digest-alg", digest_alg, "--format", "json"]
    mode = "live"
    # TZ IS PINNED, and the reason is a real field finding: gh formats the verified tlog
    # timestamp in the MACHINE'S LOCAL TIME (observed on both v2.90.0 and v2.97.0), so a
    # verifier in Riyadh got `2026-08-05T00:31:32+03:00` where a UTC container got
    # `...T21:31:32Z` — same instant, different bytes, and a UTC-only parser refused an
    # entire valid verification because of the machine's wall clock setting. Go gives the
    # TZ environment variable precedence over /etc/localtime, so pinning it here makes the
    # subprocess output identical on every machine. The parser additionally tolerates
    # offset spellings (defence in depth for a gh build that ignored TZ), but determinism
    # belongs at the source.
    extra_env = {"TZ": "UTC"}
    if bundle_path:
        argv += ["--bundle", bundle_path]
        mode = "offline-bundle"
    else:
        # LIVE mode talks to the GitHub API; the token is a credential from the VERIFIER's
        # environment. It is passed through by NAME (recorded), its value is never logged.
        for name in ("GH_TOKEN", "GITHUB_TOKEN"):
            if os.environ.get(name):
                extra_env[name] = os.environ[name]
                break
    if trusted_root_path:
        argv += ["--custom-trusted-root", trusted_root_path]
    if predicate_type:
        argv += ["--predicate-type", predicate_type]
    if signer_workflow:
        argv += ["--signer-workflow", signer_workflow]
    if deny_self_hosted:
        argv.append("--deny-self-hosted-runners")

    try:
        result = toolexec.run(argv, timeout_seconds=TIMEOUT_SECONDS, extra_env=extra_env,
                              tool_name="gh")
    except toolexec.ToolBlocked as exc:
        raise Blocked(str(exc))
    except toolexec.ToolExecError as exc:
        raise GhExecError(str(exc))

    verified = result["exitCode"] == 0
    return dict(result, mode=mode, verified=verified, executed=True, binaryPath=found,
                repository=repository, digestAlg=digest_alg,
                detail=(f"gh attestation verify ({mode}) exited {result['exitCode']}"
                        + ("" if verified else
                           f": {(result['stderr'] or result['stdout']).strip()[:300] or 'no output'}")))


def describe() -> str:
    return "\n".join([
        "GH ATTESTATION EXECUTION — GitHub's own verifier, actually run.",
        "",
        "  `gh attestation verify` is RUN against the artifact, scoped to the decision's",
        "  subject repository. Its real exit code and real --format json output decide the",
        "  result. There is no parameter for a captured verdict, and none will be added.",
        "",
        "  Offline with --bundle and --custom-trusted-root; live mode needs a token on the",
        "  verifier's environment (a credential, never an answer).",
        "",
        "  gh absent -> BLOCKED, never a fallback to a replayed verdict.",
    ])


__all__ = ["Blocked", "DEFAULT_BINARY", "GhExecError", "available", "binary", "describe",
           "run_version", "verify_attestation"]
