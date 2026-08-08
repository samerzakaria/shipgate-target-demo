"""Shared adapter machinery: the refusal ladder every authority adapter walks.

The order of the checks matters more than any single check, so it is fixed here and neither
adapter can reorder it:

  1. Is this a Decision at all?                 -> AUT_ENVIRONMENT_UNSUPPORTED
  2. Did it PASS on the merits?                 -> AUT_SEMANTIC_NOT_PASSED   (checked FIRST,
     before any tool, file or verifier is touched — attesting a failed decision must be
     impossible, not merely unlikely)
  3. Is authority configured?                   -> AUT_NOT_CONFIGURED
  4. Is the configured evidence actually there?  -> AUT_TOOL_MISSING
  5. What do the verifiers say?                 -> whatever they say
  6. Rule table, clamped to this adapter's ceiling.

An adapter NEVER raises. It is optional software operating on an already-final decision; a
crash here would be an optional component breaking a mandatory one. Every failure path
produces an `Attestation` with `ProvenanceStatus.UNAVAILABLE` and a reason.
"""
import os

from ..models import reasons as R
from ..models.decision import Attestation, ProvenanceStatus, SemanticStatus
from . import shapes
from .contracts import AuthorityConfig, AuthorityConfigError, VerifierResult, evaluate, facts

#: Evidence keys that must resolve to an existing file when configured.
_FILE_KEYS = (
    ("cosign", "versionJson"), ("cosign", "bundle"), ("cosign", "verifyStdout"),
    ("cosign", "verifyStderr"), ("cosign", "blob"), ("cosign", "publicKey"),
    ("rekor", "restEntry"), ("rekor", "cliGet"), ("rekor", "cliLogInfo"),
    ("gh", "repo"), ("gh", "environment"), ("gh", "environmentList"),
    ("gh", "environmentSecrets"),
    ("gh", "attestationArtifact"), ("gh", "attestationBundle"),
    ("gh", "attestationTrustedRoot"),
    ("oidc", "claims"),
    ("verifier", "bundle"), ("verifier", "publicKey"), ("verifier", "observation"),
)


class AuthorityAdapter:
    """Base class. Subclasses set `name`, `version`, `ceiling`, `verifier_classes`, `mode`."""

    name = "authority"
    version = "shipgate-authority/4.2.4"
    mode = "ci"
    ceiling = ProvenanceStatus.UNAVAILABLE
    verifier_classes = ()

    def __init__(self, config=None, registry=None):
        self.registry = registry or shapes.registry()
        self.config_error = ""
        try:
            self.config = AuthorityConfig.coerce(config)
        except AuthorityConfigError as exc:
            self.config = None
            self.config_error = str(exc)
        self.verifiers = tuple(cls() for cls in self.verifier_classes)

    # -- availability --------------------------------------------------------------------
    def availability(self):
        """(configured: bool, reason_code: str, detail: str). Never raises, never fabricates."""
        if self.config_error:
            return False, R.AUT_NOT_CONFIGURED, f"authority config is invalid: {self.config_error}"
        if self.config is None:
            return (False, R.AUT_NOT_CONFIGURED,
                    "no authority configuration was supplied; the VERIFIED workflow needs none")
        if self.config.mode != self.mode:
            return (False, R.AUT_ENVIRONMENT_UNSUPPORTED,
                    f"config mode is {self.config.mode!r} but this is the {self.mode!r} adapter")
        if not self.config.configured_sections():
            return (False, R.AUT_NOT_CONFIGURED,
                    "the authority config names no evidence at all")
        missing = self._missing_files()
        if missing:
            return (False, R.AUT_TOOL_MISSING,
                    "configured evidence is missing on disk: " + ", ".join(missing[:6]))
        blocked = self._blocking_shapes()
        if blocked:
            # Configured, but a shape it depends on has never been seen. Still True for
            # "configured" — the operator did their part; the kit has not.
            return (True, R.AUT_OUTPUT_SHAPE_UNKNOWN,
                    "configured, but these required output shapes are BLOCKED (no real "
                    "capture): " + ", ".join(blocked))
        return True, self.ready_reason(), ""

    def ready_reason(self):
        """The reason code reported when everything the adapter needs is present."""
        return R.AUT_CI_ATTESTED

    def _missing_files(self):
        missing = []
        for section, key in _FILE_KEYS:
            path = self.config.resolve(section, key)
            if path and not os.path.isfile(path):
                missing.append(f"{section}.{key}={path}")
        return missing

    def _blocking_shapes(self):
        """Shape requirements this registry cannot satisfy.

        A `requires` element that is a TUPLE is a redundant set — the same serialisation
        captured more than once — and is satisfied by ANY validated member. It is reported as
        blocking only when EVERY member is blocked, which is the honest reading: one intact
        capture of a shape is one capture of that shape.
        """
        needed = []
        for verifier in self.verifiers:
            for requirement in verifier.requires:
                group = (requirement,) if isinstance(requirement, str) else tuple(requirement)
                if any(self.registry.status(s) == shapes.VALIDATED for s in group):
                    continue
                label = group[0] if len(group) == 1 else "any of " + "/".join(group)
                if label not in needed:
                    needed.append(label)
        return needed

    # -- attestation ---------------------------------------------------------------------
    def attest(self, decision):
        """Produce an `Attestation` ABOUT `decision`. Never returns None, never raises."""
        digest, guard = self._guard(decision)
        if guard is not None:
            return guard

        configured, code, detail = self.availability()
        if not configured:
            return self._unavailable(digest, (code,), detail)

        results = []
        for verifier in self.verifiers:
            try:
                results.append(verifier.verify(decision, self.config))
            except Exception as exc:                      # noqa: BLE001 - see module docstring
                # A verifier bug must not become a crash in an optional kit, and it must
                # certainly not become a pass.
                results.append(_verifier_crash(verifier, exc))

        status, codes, why = evaluate(decision.semantic_status, results, ceiling=self.ceiling)
        merged = facts(results)
        return Attestation(
            provenance_status=status,
            decision_digest=digest,
            verifier=self.name,
            verifier_version=self.version,
            reason_codes=codes,
            identity=merged["identity"],
            binding=merged["binding"],
            freshness=merged["freshness"],
            principals=tuple(p for p in (merged["principal"],) if p),
            detail=_compose_detail(why, results),
        )

    # -- refusals ------------------------------------------------------------------------
    def _guard(self, decision):
        """(digest, refusal|None). Steps 1 and 2 of the ladder."""
        try:
            digest = decision.digest()
            semantic = decision.semantic_status
        except (AttributeError, TypeError) as exc:
            return "", Attestation(
                provenance_status=ProvenanceStatus.UNAVAILABLE,
                decision_digest="", verifier=self.name, verifier_version=self.version,
                reason_codes=(R.AUT_ENVIRONMENT_UNSUPPORTED,),
                detail=f"not an attestable Decision: {exc}")

        if semantic is not SemanticStatus.PASSED:
            return digest, self._unavailable(
                digest, (R.AUT_SEMANTIC_NOT_PASSED,),
                f"decision semantic status is {getattr(semantic, 'value', semantic)!r}; no "
                "authority adapter may attest a decision that did not pass on the merits. "
                "No tool was invoked and no evidence was read.")

        incomplete = _incompleteness(decision)
        if incomplete:
            return digest, self._unavailable(
                digest, (R.AUT_SEMANTIC_NOT_PASSED,),
                f"decision is marked PASSED but is incomplete: {incomplete}. Refusing to "
                "attest a decision whose own record contradicts its status.")
        return digest, None

    def _unavailable(self, digest, codes, detail):
        return Attestation(
            provenance_status=ProvenanceStatus.UNAVAILABLE,
            decision_digest=digest, verifier=self.name, verifier_version=self.version,
            reason_codes=tuple(codes), detail=detail)


def _incompleteness(decision):
    """Why this PASSED decision cannot be taken at face value. '' when it can."""
    failing = [c for c in decision.reason_codes if c in R.SEMANTIC_FAILING]
    if failing:
        return f"it carries failing reason codes {failing}"
    if decision.break_glass:
        return ("it was produced under a recorded break-glass override, which is never a "
                "VERIFIED result")
    if not decision.checks:
        return "it contains no check results at all"
    unrun = [c.check_id for c in decision.checks if c.required and not c.passed]
    if unrun:
        return f"required checks {unrun} did not pass"
    return ""


def _verifier_crash(verifier, exc):
    return VerifierResult.refusal(
        getattr(verifier, "name", "unknown"), getattr(verifier, "version", "0"),
        R.AUT_ENVIRONMENT_UNSUPPORTED,
        f"verifier raised {type(exc).__name__}: {exc}. Treated as a refusal.")


def _compose_detail(why, results):
    parts = [why]
    for res in results:
        mark = "OK" if res.established else "REFUSED"
        parts.append(f"[{res.verifier}: {mark}] {res.detail}")
    return " | ".join(p for p in parts if p)


__all__ = ["AuthorityAdapter"]
