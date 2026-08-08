"""Run cosign, rather than reading a file that claims cosign ran.

THE FINDING THIS ANSWERS. `CosignBundleVerifier._verdict` read `cosign.verifyExitCode` — an
integer typed into the authority config — plus stdout and stderr from operator-supplied paths,
and treated `0` with the text `Verified OK` as cosign's verdict. Cosign is what checks the
certificate signature, the chain to the Sigstore root and the SCT; the kit does none of that.
So the one step that actually establishes cryptographic identity was a string the operator
wrote next to a number the operator chose.

HOW THE PROCESS IS ACTUALLY SPAWNED. v4.2 moved the spawn itself into `toolexec.run` — the
ONE subprocess discipline shared by every trust-tool executor (cosign here, gh in
`ghexec.py`) — so this module no longer imports `subprocess` at all. The justification for
running a process is unchanged and still has to be stated rather than assumed: this path does
not run anything the target controls. It runs ONE pinned binary, found on the verifier's own
PATH or named explicitly by the verifier operator, with an argument list this module builds.
No shell, no target-supplied argv, no target-supplied environment. The bundle being checked
is data passed to that binary, never code.

That distinction is the whole justification, and if it ever stops being true — if a config key
starts contributing to argv, if `shell=True` appears, if the binary path becomes attacker
reachable — the exemption is void and this module has become the hole it was written to close.

WHAT EXECUTION BUYS, AND WHAT IT DOES NOT. Running cosign means the signature, the chain and
the SCT were checked by the tool that knows how, on THIS machine, over THIS bundle, now.
It does not make the kit a Sigstore implementation, it does not verify Fulcio itself, and it
does not tell you the signer is trustworthy — only that the bundle verifies against the
identity constraints the verifier operator pinned. Those constraints are still the operator's
judgement; what is no longer the operator's to assert is the ANSWER.
"""
import json
import os
from typing import Any, Dict, List, Optional

from . import toolexec

DEFAULT_BINARY = "cosign"
TIMEOUT_SECONDS = 120

#: Text cosign prints on success. Matched on the real process's own output, not on a file.
SUCCESS_TOKEN = "Verified OK"


class CosignExecError(Exception):
    """cosign could not be run, or produced something unusable."""


class Blocked(CosignExecError):
    """cosign is not available here. BLOCKED — never a fallback to a replayed verdict.

    Separate from a verification FAILURE on purpose: "cosign is not installed" and "this
    signature is invalid" must never collapse into one outcome.
    """


def binary(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the cosign binary from an explicit path, the environment, or PATH."""
    return toolexec.resolve_binary(DEFAULT_BINARY, "SHIPGATE_COSIGN_BINARY", explicit)


def available(explicit: Optional[str] = None):
    """(usable, detail). Never raises, so `doctor` can report it without running anything."""
    found = binary(explicit)
    if not found:
        return False, ("cosign is not on this verifier's PATH and SHIPGATE_COSIGN_BINARY is "
                       "unset, so no signature can be checked by the tool that knows how. "
                       "The verdict is BLOCKED, not read from a file.")
    try:
        version = run_version(found)
    except CosignExecError as exc:
        return False, str(exc)
    return True, f"cosign {version.get('gitVersion') or version.get('GitVersion') or '?'} at {found}"


def _run(argv: List[str], cwd: Optional[str] = None) -> Dict[str, Any]:
    """One cosign invocation. No shell, explicit argv, bounded time.

    v4.2: the actual spawn lives in `toolexec.run` — ONE subprocess discipline shared with
    the gh executor, so a fix to either applies to both. The exception mapping preserves this
    module's contract exactly: Blocked for "could not run", CosignExecError for "did not
    finish", and a nonzero exit as a RESULT, never an exception.
    """
    try:
        result = toolexec.run(argv, timeout_seconds=TIMEOUT_SECONDS, cwd=cwd,
                              extra_env={"COSIGN_EXPERIMENTAL": "0"}, tool_name="cosign")
    except toolexec.ToolBlocked as exc:
        raise Blocked(str(exc))
    except toolexec.ToolExecError as exc:
        raise CosignExecError(str(exc))
    return {"argv": argv, "exitCode": result["exitCode"],
            "stdout": result["stdout"], "stderr": result["stderr"]}


def run_version(explicit: Optional[str] = None) -> Dict[str, Any]:
    found = binary(explicit)
    if not found:
        raise Blocked(available(explicit)[1])
    result = _run([found, "version", "--json"])
    if result["exitCode"] != 0:
        raise CosignExecError(f"`cosign version --json` exited {result['exitCode']}: "
                              f"{result['stderr'][:200]}")
    try:
        return json.loads(result["stdout"])
    except ValueError as exc:
        raise CosignExecError(f"`cosign version --json` did not produce JSON: {exc}")


def verify_blob(blob_path: str, bundle_path: str, *, key_path: Optional[str] = None,
                certificate_identity: Optional[str] = None,
                certificate_oidc_issuer: Optional[str] = None,
                explicit_binary: Optional[str] = None) -> Dict[str, Any]:
    """Actually run `cosign verify-blob`. Returns the REAL exit code and output.

    Either a public key (keyed) or an identity plus issuer (keyless) must be given. Refusing
    to run without one is deliberate: `cosign verify-blob` with no identity constraint will
    happily verify a signature made by anybody, and a verifier that accepted that would have
    re-created the hole one layer down — a real execution producing a meaningless verdict.
    """
    found = binary(explicit_binary)
    if not found:
        raise Blocked(available(explicit_binary)[1])
    if not os.path.isfile(blob_path):
        raise CosignExecError(f"nothing to verify: {blob_path} does not exist")
    if not os.path.isfile(bundle_path):
        raise CosignExecError(f"no bundle at {bundle_path}")

    argv = [found, "verify-blob", "--bundle", bundle_path]
    if key_path:
        argv += ["--key", key_path]
        mode = "keyed"
    elif certificate_identity and certificate_oidc_issuer:
        argv += ["--certificate-identity", certificate_identity,
                 "--certificate-oidc-issuer", certificate_oidc_issuer]
        mode = "keyless"
    else:
        raise CosignExecError(
            "cosign execution needs either a public key or BOTH a certificate identity and "
            "an OIDC issuer. Running verify-blob without an identity constraint verifies "
            "that SOMEBODY signed this, which is not a fact worth recording.")
    argv.append(blob_path)

    result = _run(argv)
    combined = f"{result['stdout']}\n{result['stderr']}"
    verified = result["exitCode"] == 0 and SUCCESS_TOKEN in combined
    return dict(result, mode=mode, verified=verified, executed=True, binaryPath=found,
                detail=(f"cosign verify-blob ({mode}) exited {result['exitCode']}"
                        + ("" if verified else
                           f": {combined.strip()[:300] or 'no output'}")))


def describe() -> str:
    return "\n".join([
        "COSIGN EXECUTION — the verdict is produced here, not read.",
        "",
        "  `cosign verify-blob` is RUN against the bundle, with an identity constraint that",
        "  the verifier operator pins. Its real exit code and real stdout decide the result.",
        "  A `verifyExitCode` in the config no longer establishes anything.",
        "",
        "  Refuses to run with no identity constraint: verifying that SOMEBODY signed this",
        "  is not a fact worth recording.",
        "",
        "  cosign absent -> BLOCKED, never a fallback to a captured verdict.",
    ])
