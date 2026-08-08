"""The four verifiers the two adapters are built from.

Each one reports FACTS, never a status:

    CosignBundleVerifier          does a signature bind THIS decision      -> binding
                                  digest, and — keyless only — whose          (+ identity)
                                  Fulcio certificate signed it?
    RekorTransparencyVerifier     is that signature in a public log,       -> freshness
                                  and how old?
    GithubOidcIdentityVerifier    can a raw OIDC claim set establish       -> nothing, ever
                                  identity? (no: unverified JWT)
    GithubEnvironmentPrincipalVerifier  did a principal the builder        -> principal
                                        cannot impersonate have to act?

Note where identity actually comes from. NOT from the OIDC claim set — this kit cannot verify
a JWT signature, so those claims are corroboration and `GithubOidcIdentityVerifier` exists to
say so precisely and to catch a wrong issuer, audience or repository early. Identity comes
from the keyless cosign path, where Fulcio binds the OIDC identity into a certificate that
cosign verifies against Sigstore's roots, and `CosignBundleVerifier` then checks that the
identity in that certificate is the decision's subject.

`contracts.evaluate` turns facts into a `ProvenanceStatus`. A verifier that cannot answer
returns a refusal with an AUT_ code — never a partial success, never a warning attached to a
pass. A refusal from a verifier does not by itself block an award: `evaluate` looks at which
FACTS exist, and drops any reason code the award contradicts. Nothing here raises on bad
evidence: this kit is optional, and an optional kit must not be able to crash a run whose
semantic decision is already final.
"""
import hashlib
import json
import time

from ..models import reasons as R
from .contracts import Verifier, VerifierResult
from .parsers import cosign as cosign_parser
from .parsers import gh as gh_parser
from .parsers import ghattest as ghattest_parser
from .parsers import oidc as oidc_parser
from .parsers import rekor as rekor_parser


def _read(path):
    """(bytes, error). Bytes, not text — decoding is the parser's job (BOMs are real)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(), None
    except OSError as exc:
        return None, f"{path}: {exc.strerror or exc}"


def _subject_pins(decision, config):
    """(repository, commit, mismatch_detail).

    The subject ALWAYS comes from the DECISION, which the semantic engine already fixed and
    which nothing here can change. `expectedSubject` in the config is a CROSS-CHECK, not an
    override: if it disagrees with the decision, that is a refusal. Letting config supply the
    subject would be exactly the "identity from a file the builder writes" hole.
    """
    repository = decision.subject.repository
    commit = decision.subject.commit
    expected = config.expected_subject or {}
    for key, actual in (("repository", repository), ("commit", commit)):
        claimed = expected.get(key)
        if claimed is not None and str(claimed).strip().lower() != str(actual).lower():
            return repository, commit, (
                f"authority config expectedSubject.{key}={claimed!r} disagrees with the "
                f"decision's subject {actual!r}; the decision is authoritative and the config "
                "does not get to redefine what was evaluated")
    return repository, commit, ""


class CosignBundleVerifier(Verifier):
    """Binding always; identity too, but ONLY from a keyless bundle.

    A KEYED bundle proves possession of a key. Whoever ran the build had that key, so it
    establishes `binding` and nothing else — a key says "the same someone signed this", never
    "this someone".

    A KEYLESS bundle is different. Fulcio issues a ten-minute certificate that names the
    workflow, repository, commit and runner, and logs it to a CT log. That IS an external
    identity — but only if two independent things hold, and this verifier requires both:

      1. `cosign verify-blob` returned the captured success text. Cosign is what checks the
         certificate's signature, its chain to the Sigstore root and its SCT; this kit does
         none of that and must not pretend to.
      2. the identity INSIDE the certificate is the decision's subject repository. Step 1
         alone is not enough: an operator can pass `--certificate-identity-regexp '.*'` and
         get a cheerful "Verified OK" for a certificate belonging to someone else entirely.
         Reading the DER ourselves and comparing is what closes that hole.

    An OIDC claim set, when configured, is used as CORROBORATION here: it and the certificate
    describe the same signing event, and a disagreement between them is a refusal.
    """
    name = "cosign-bundle"
    version = cosign_parser.VERSION_GATE.describe()
    requires = (cosign_parser.KEYED_V03_SHAPES, cosign_parser.SHAPE_VERSION,
                cosign_parser.VERIFY_OK_SHAPES, cosign_parser.VERIFY_FAIL_SHAPES)

    def verify(self, decision, config):
        bundle_path = config.resolve("cosign", "bundle")
        if not bundle_path:
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                "cosign.bundle is not configured; nothing binds a signature "
                                "to this decision")

        # 1. Which cosign produced this? An unidentified tool version is not trusted.
        version_path = config.resolve("cosign", "versionJson")
        if not version_path:
            return self._refuse(R.AUT_TOOL_VERSION_UNSUPPORTED,
                                "cosign.versionJson is not configured; this kit refuses to "
                                "parse output from an unidentified cosign version "
                                f"(supported: {cosign_parser.VERSION_GATE.describe()})")
        raw, err = _read(version_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"cosign version output unreadable: {err}")
        version_res = cosign_parser.parse_version(raw)
        if not version_res.ok:
            return self._refuse(version_res.reason_code, version_res.detail)
        cosign_version = version_res.data["version"]

        # 2. cosign's own verdict. A missing verdict is not a pass.
        verdict_res = self._verdict(config)
        if verdict_res is not None:
            return verdict_res

        # 3. The bundle itself, and whether it is about THIS decision.
        raw, err = _read(bundle_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"cosign bundle unreadable: {err}")
        bundle_res = cosign_parser.parse_bundle(raw, cosign_version=cosign_version)
        if not bundle_res.ok:
            return self._refuse(bundle_res.reason_code, bundle_res.detail)

        binding_res = cosign_parser.check_binding(bundle_res.data, decision.digest())
        if not binding_res.ok:
            return self._refuse(binding_res.reason_code, binding_res.detail)

        bundle = bundle_res.data
        binding = dict(binding_res.data, cosignVersion=cosign_version,
                       keyless=bool(bundle.get("keyless")),
                       inclusionProofVerified=bundle.get("inclusionProofVerified", False))

        # 4. Identity — keyless only, and only when the certificate names THIS subject.
        identity = None
        detail = ("cosign verify-blob returned the captured success text and the bundle's "
                  "signed digest is this decision's digest")
        if bundle.get("keyless"):
            repository, _commit, mismatch = _subject_pins(decision, config)
            if mismatch:
                return self._refuse(R.AUT_BINDING_MISMATCH, mismatch)

            claims = self._claims(config, bundle)
            if isinstance(claims, VerifierResult):
                return claims

            check = cosign_parser.check_certificate_identity(
                bundle, expected_repository=repository, claims=claims)
            if not check.ok:
                return self._refuse(check.reason_code, check.detail)

            identity = dict(
                bundle["identity"],
                kind="fulcio-keyless-certificate",
                verifiedBy="cosign verify-blob",
                certificate=bundle["certificate"],
                corroboratedByOidcClaims=claims is not None,
                agreedFields=[a["field"] for a in check.data["agreements"]],
            )
            detail = (
                "cosign verified the signature and certificate chain, and the certificate's "
                f"own identity names {check.data['certificateRepository']!r}, which is this "
                "decision's subject")

        return VerifierResult(
            verifier=self.name, verifier_version=f"cosign {cosign_version}", established=True,
            binding=binding, identity=identity, detail=detail,
        )

    def _claims(self, config, bundle):
        """The OIDC claim set as CORROBORATION. None when not configured; a refusal when it
        is configured and disagrees with itself or with the signing event."""
        claims_path = config.resolve("oidc", "claims")
        if not claims_path:
            return None
        raw, err = _read(claims_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"OIDC claim set unreadable: {err}")
        parsed = oidc_parser.parse_claims(raw)
        if not parsed.ok:
            return self._refuse(parsed.reason_code, parsed.detail)
        # The token must have been live WHEN THE SIGNATURE WAS LOGGED, not now. A recorded
        # claim set is always expired by the time anyone reads it.
        ok, code, why = oidc_parser.check_claims(
            parsed.data["claims"],
            expected_audience=config.oidc.get("expectedAudience"),
            at_time=bundle.get("integratedTime"))
        if not ok:
            return self._refuse(code, f"OIDC corroboration failed: {why}")
        return parsed.data["claims"]

    _execution = None

    def _diagnostic_replay(self, config):
        """Describe any captured verdict as DIAGNOSTIC, so it is neither used nor discarded.

        A replayed exit code still tells a human something — usually that the CI job thought
        it succeeded — and deleting it would make a real failure harder to debug. What it may
        never do is contribute to an outcome. Recording it in the refusal keeps it visible
        and unmistakably non-load-bearing.
        """
        claimed = config.cosign.get("verifyExitCode")
        if claimed is None:
            return ""
        return (f"[DIAGNOSTIC ONLY, contributes to no outcome: a captured "
                f"verifyExitCode={claimed} was supplied.]")

    def _execute(self, config):
        """Run cosign when the config asks for it. None = not requested, fall through.

        Returns a refusal when execution was requested and failed, and None when it succeeded
        — because success here means the caller should continue with the rest of its checks,
        not that the whole verifier is finished.
        """
        self._execution = None
        blob = config.resolve("cosign", "blob")
        if not blob:
            return None
        try:
            from . import cosignexec
        except ImportError as exc:  # pragma: no cover
            return self._refuse(R.AUT_NOT_CONFIGURED, f"cosign runner unavailable: {exc}")
        bundle = config.resolve("cosign", "bundle")
        if not bundle:
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                "cosign.blob is set for live execution but cosign.bundle is "
                                "not; there is nothing to verify it against")
        try:
            result = cosignexec.verify_blob(
                blob, bundle,
                key_path=config.resolve("cosign", "publicKey"),
                certificate_identity=config.cosign.get("certificateIdentity"),
                certificate_oidc_issuer=config.cosign.get("certificateOidcIssuer"))
        except cosignexec.Blocked as exc:
            return self._refuse(R.AUT_TOOL_MISSING, f"BLOCKED: {exc}")
        except cosignexec.CosignExecError as exc:
            return self._refuse(R.AUT_TOOL_MISSING, str(exc))
        if not result["verified"]:
            return self._refuse(R.AUT_IDENTITY_NOT_ESTABLISHED,
                                f"cosign REJECTED this bundle: {result['detail']}")
        self._execution = result
        return None

    def _verdict(self, config):
        """None when cosign said 'Verified OK'; a refusal otherwise."""
        # EXECUTE, don't replay. `verifyExitCode` used to be an integer typed into the config
        # and `verifyStdout` a file the operator wrote, which meant the single step that
        # establishes cryptographic identity was the operator asserting the answer. When a
        # blob and an identity constraint are configured, cosign is RUN and its real exit code
        # decides. A replayed verdict can no longer establish anything on its own.
        executed = self._execute(config)
        if executed is not None:
            return executed
        if getattr(self, "_execution", None) is None:
            # NO FALLBACK. Execution used to be opt-in: omit `cosign.blob` and the verifier
            # dropped back to `verifyExitCode` plus a stdout file, which is the replayed
            # verdict the audit found in the first place. An opt-in fix is not a fix — it is
            # the same hole behind one missing key.
            replayed = self._diagnostic_replay(config)
            return self._refuse(
                R.AUT_NOT_CONFIGURED,
                (f"{replayed} " if replayed else "")
                + "cosign was not RUN. Configure cosign.blob (the signed artifact) together "
                "with cosign.bundle and an identity constraint (cosign.publicKey, or "
                "cosign.certificateIdentity + cosign.certificateOidcIssuer). A captured "
                "verifyExitCode and a stdout file cannot establish identity or binding: "
                "they are the operator asserting the answer to the only question that "
                "proves anything.")
        stdout = stderr = ""
        for key, target in (("verifyStdout", "stdout"), ("verifyStderr", "stderr")):
            path = config.resolve("cosign", key)
            if not path:
                continue
            raw, err = _read(path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING,
                                    f"cosign {target} unreadable: {err}")
            if target == "stdout":
                stdout = raw
            else:
                stderr = raw
        verdict = cosign_parser.parse_verify_blob(exit_code, stdout, stderr)
        if not verdict.ok:
            # A verification failure is a REFUSAL, propagated verbatim. Never downgraded to a
            # warning, never retried with laxer rules.
            return self._refuse(verdict.reason_code, verdict.detail)
        return None


class RekorTransparencyVerifier(Verifier):
    """Freshness: the entry is really in the public log, and it was made recently.

    `integratedTime` from the REST entry is the freshness source. The rekor-cli shape is
    accepted as corroboration but can never supply the proof — it omits the inclusion proof
    by default, which this verifier detects and says out loud.
    """
    name = "rekor-transparency"
    version = rekor_parser.VERSION_GATE.describe()
    #: REST_SHAPES is one serialisation captured twice (the 2021 entry and the 2026-08-06 one);
    #: the parser needs only one of the pair intact, so it is declared as a redundant set.
    requires = (rekor_parser.REST_SHAPES,)

    def verify(self, decision, config):
        rest_path = config.resolve("rekor", "restEntry")
        if not rest_path:
            cli_path = config.resolve("rekor", "cliGet")
            if cli_path:
                return self._refuse(
                    R.AUT_OUTPUT_SHAPE_UNKNOWN,
                    "only rekor.cliGet is configured. `rekor-cli get --format json` omits the "
                    "Verification/InclusionProof block by default, so it cannot prove "
                    "inclusion. Configure rekor.restEntry "
                    "(GET /api/v1/log/entries?logIndex=N).")
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                "rekor.restEntry is not configured; there is no transparency "
                                "evidence to check")

        raw, err = _read(rest_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"rekor REST entry unreadable: {err}")
        entry_res = rekor_parser.parse_rest_entry(raw)
        if not entry_res.ok:
            return self._refuse(entry_res.reason_code, entry_res.detail)
        entry = entry_res.data

        fresh_res = rekor_parser.freshness(entry, config.freshness_max_age_seconds)
        if not fresh_res.ok:
            return self._refuse(fresh_res.reason_code, fresh_res.detail)

        checkpoint = self._verified_checkpoint(entry)
        if isinstance(checkpoint, VerifierResult):
            return checkpoint

        corroboration = self._corroborate(config, entry)
        if isinstance(corroboration, VerifierResult):
            return corroboration

        return VerifierResult(
            verifier=self.name, verifier_version=self.version, established=True,
            freshness=dict(fresh_res.data,
                           uuid=entry["uuid"],
                           logIdHex=entry["logIdHex"],
                           treeSize=entry["treeSize"],
                           rootHashHex=entry["rootHashHex"],
                           inclusionProofVerified=True,
                           shardOffset=entry.get("shardOffset"),
                           shardOffsetVerified=bool(
                               (corroboration.get("shardOffset") or {}).get(
                                   "shardOffsetVerified")),
                           boundToBundle=bool(corroboration.get("cosignBundle")),
                           checkpointSignatureVerified=True,
                           checkpointTrustRoot=checkpoint["trustRootDigest"],
                           checkpointOrigin=checkpoint["originHost"],
                           signedEntryTimestampVerified=False,
                           corroboration=corroboration),
            detail=("the RFC 6962 inclusion proof recomputes root "
                    f"{entry['rootHashHex'][:16]}…, and a checkpoint signed by the PINNED "
                    f"{checkpoint['originHost']} key attests that same root — so this entry is "
                    f"in the public log, not merely internally consistent. "
                    "signedEntryTimestamp remains shape-checked only."),
        )

    def _verified_checkpoint(self, entry):
        """Verify the checkpoint against the pinned Rekor key, or REFUSE.

        THIS IS THE JOINT THE AUDIT FOUND. Recomputing an inclusion proof proves the entry is
        consistent with a root hash; it says nothing about whether that root is Rekor's. An
        attacker who supplies both the entry and the root gets a passing proof over their own
        tree. The checkpoint is what closes it: Rekor signs (origin, treeSize, rootHash), so a
        signature over a checkpoint naming the SAME root the proof recomputed is the log
        asserting this entry's inclusion.

        Both halves are required. A verified signature over a DIFFERENT root proves only that
        Rekor signed something else, and letting that pass would reintroduce the hole with
        extra steps.
        """
        from . import trustroot

        checkpoint = (entry.get("checkpoint") or {})
        raw = checkpoint.get("raw")
        if not raw:
            return self._refuse(
                R.AUT_OUTPUT_SHAPE_UNKNOWN,
                "the REST entry carries no raw checkpoint, so the recomputed Merkle root "
                "cannot be tied to anything Rekor signed; an inclusion proof against an "
                "unattested root is internal consistency, not inclusion")
        try:
            fact = trustroot.verify_checkpoint(raw)
        except trustroot.TrustRootError as exc:
            return self._refuse(R.AUT_FRESHNESS_EXPIRED, f"checkpoint rejected: {exc}")

        if fact["rootHashHex"] != entry["rootHashHex"]:
            return self._refuse(
                R.AUT_BINDING_MISMATCH,
                f"the checkpoint is validly signed but attests root "
                f"{fact['rootHashHex'][:16]}…, while the inclusion proof recomputes "
                f"{entry['rootHashHex'][:16]}…; Rekor signed a different tree than the one "
                f"this proof was built against")
        if fact["treeSize"] != entry["treeSize"]:
            return self._refuse(
                R.AUT_BINDING_MISMATCH,
                f"checkpoint tree size {fact['treeSize']} does not match the entry's "
                f"{entry['treeSize']}")
        return fact

    def _corroborate(self, config, entry):
        """Optional cross-checks against the other shapes. Any DISAGREEMENT is a refusal —
        two sources that contradict each other are not two pieces of evidence."""
        notes = {}

        # GET /api/v1/log: the only document that can prove the shard offset. Without it the
        # gap between the entry's GLOBAL logIndex and its SHARD-LOCAL proof index is merely
        # plausible; with it, it is arithmetic.
        info_rest_path = config.resolve("rekor", "restLogInfo")
        if info_rest_path:
            raw, err = _read(info_rest_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING,
                                    f"rekor REST loginfo unreadable: {err}")
            info_res = rekor_parser.parse_rest_loginfo(raw)
            if not info_res.ok:
                return self._refuse(info_res.reason_code, info_res.detail)
            offset_res = rekor_parser.check_shard_offset(entry, info_res.data)
            if not offset_res.ok:
                return self._refuse(offset_res.reason_code, offset_res.detail)
            notes["shardOffset"] = offset_res.data

        # The bundle, when one is configured: does the signature's own record of its log entry
        # agree with what the log says? Two independent sources describing one entry. A
        # disagreement is a REFUSAL — never a merge, never "prefer the newer one".
        bundle_path = config.resolve("cosign", "bundle")
        if bundle_path:
            raw, err = _read(bundle_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING, f"cosign bundle unreadable: {err}")
            # No version is passed: CosignBundleVerifier owns the version gate, and a
            # cross-check must not be able to fail for a reason that is not a disagreement.
            bundle_res = cosign_parser.parse_bundle(raw)
            if not bundle_res.ok:
                return self._refuse(bundle_res.reason_code, bundle_res.detail)
            if bundle_res.data.get("inclusionProofPresent") is False:
                # The legacy keyless bundle has no proof and no leaf to compare. Say so rather
                # than silently skipping a check the caller may believe ran.
                notes["cosignBundle"] = {
                    "crossChecked": False,
                    "why": "the legacy cosign bundle carries no inclusion proof, so there is "
                           "no logged leaf in it to compare against this entry"}
            else:
                agree_res = cosign_parser.check_tlog_agreement(bundle_res.data, entry)
                if not agree_res.ok:
                    return self._refuse(agree_res.reason_code, agree_res.detail)
                notes["cosignBundle"] = dict(agree_res.data, crossChecked=True)
        cli_path = config.resolve("rekor", "cliGet")
        if cli_path:
            raw, err = _read(cli_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING, f"rekor-cli output unreadable: {err}")
            cli_res = rekor_parser.parse_cli_get(raw, rekor_version=config.rekor.get("version"))
            if not cli_res.ok:
                return self._refuse(cli_res.reason_code, cli_res.detail)
            cli = cli_res.data
            if cli["logIndex"] != entry["logIndex"] or \
                    cli["integratedTime"] != entry["integratedTime"]:
                return self._refuse(
                    R.AUT_BINDING_MISMATCH,
                    f"rekor-cli reports entry {cli['logIndex']}@{cli['integratedTime']} but the "
                    f"REST entry is {entry['logIndex']}@{entry['integratedTime']}")
            notes["cliGet"] = {"logIndex": cli["logIndex"],
                               "inclusionProofPresent": cli["inclusionProofPresent"]}

        info_path = config.resolve("rekor", "cliLogInfo")
        if info_path:
            raw, err = _read(info_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING, f"rekor loginfo unreadable: {err}")
            info_res = rekor_parser.parse_loginfo(raw,
                                                  rekor_version=config.rekor.get("version"))
            if not info_res.ok:
                return self._refuse(info_res.reason_code, info_res.detail)
            info = info_res.data
            tree_id = entry["checkpoint"].get("treeId")
            if tree_id is not None and info["treeId"] != tree_id:
                return self._refuse(
                    R.AUT_BINDING_MISMATCH,
                    f"loginfo describes tree {info['treeId']} but the entry's checkpoint is "
                    f"from tree {tree_id}; these are different logs")
            notes["logInfo"] = {"treeId": info["treeId"],
                                "activeTreeSize": info["activeTreeSize"]}
        return notes


class GhAttestationVerifier(Verifier):
    """GitHub artifact attestation: identity, binding and freshness from GitHub's own
    verifier, actually run.

    THE DIVISION OF LABOUR, stated because it is what makes this adapter honest:

      gh proves the attestation is REAL — certificate chain to the Sigstore/GitHub roots,
      SCT, transparency-log proof, artifact digest against the in-toto subject. This kit
      does not reimplement any of that cryptography and must not pretend to.

      this verifier proves the attestation is about THIS decision — the artifact on disk
      re-hashes to the decision's own `subject.artifactDigest` (computed HERE, not read
      from anything), the certificate's repository and commit are the decision's subject,
      and the run id agrees with the configured one when there is one.

    WHAT CANNOT INFLUENCE THE OUTCOME. There is no key for a captured stdout, a captured
    exit code, or an expected identity: the verdict is the exit code of the subprocess this
    verifier just ran, the identity constraint gh enforces is the DECISION's subject
    repository, and the builder-authorisation judgement belongs to the external policy
    (`enforcement.builder_authorized`), never to a config value. `--deny-self-hosted-runners`
    is always passed, and the certificate's own runnerEnvironment is re-checked after.

    This establishes CI-tier facts. It says nothing about whether anyone independent looked;
    the principal axis is untouched, exactly as with the cosign path.
    """
    name = "gh-artifact-attestation"
    version = ghattest_parser.VERSION_GATE.describe()
    requires = (ghattest_parser.SHAPE_VERSION, ghattest_parser.SHAPE_VERIFY)

    _DIGEST_LENGTHS = {"sha256": 64, "sha512": 128}

    def verify(self, decision, config):
        artifact = config.resolve("gh", "attestationArtifact")
        if not artifact:
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                "gh.attestationArtifact is not configured; there is no "
                                "artifact to verify a GitHub attestation for")

        repository, commit, mismatch = _subject_pins(decision, config)
        if mismatch:
            return self._refuse(R.AUT_BINDING_MISMATCH, mismatch)

        expected_digest = (getattr(decision.subject, "artifact_digest", None) or "").lower()
        if not expected_digest:
            return self._refuse(
                R.AUT_BINDING_MISMATCH,
                "the decision carries no subject.artifactDigest, so an artifact attestation "
                "has nothing to bind to. A matching repository alone is a weaker claim "
                "wearing a stronger one's clothes.")
        digest_alg = str(config.gh.get("attestationDigestAlg") or "sha256")
        if digest_alg not in self._DIGEST_LENGTHS:
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                f"gh.attestationDigestAlg {digest_alg!r} is not supported "
                                f"(sha256, sha512)")
        if len(expected_digest) != self._DIGEST_LENGTHS[digest_alg]:
            return self._refuse(
                R.AUT_BINDING_MISMATCH,
                f"the decision's artifactDigest is {len(expected_digest)} hex chars, which "
                f"is not a {digest_alg} digest; the digest and the algorithm disagree")

        # RE-HASH THE ARTIFACT OURSELVES. gh checks the artifact against the attestation's
        # subject; nothing so far checks it against the DECISION. An operator who points
        # gh.attestationArtifact at a different (validly attested) file must be caught here,
        # by arithmetic, not by trust in the filename.
        try:
            hasher = hashlib.new(digest_alg)
            with open(artifact, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    hasher.update(chunk)
            actual_digest = hasher.hexdigest()
        except OSError as exc:
            return self._refuse(R.AUT_TOOL_MISSING,
                                f"the artifact is unreadable: {exc}")
        if actual_digest != expected_digest:
            return self._refuse(
                R.AUT_BINDING_MISMATCH,
                f"the artifact on disk hashes to {actual_digest[:16]}… but the decision's "
                f"subject.artifactDigest is {expected_digest[:16]}…; whatever gh verifies, "
                f"it is not the artifact this decision judged")

        try:
            from . import ghexec
        except ImportError as exc:  # pragma: no cover
            return self._refuse(R.AUT_NOT_CONFIGURED, f"gh runner unavailable: {exc}")
        try:
            gh_version = ghexec.run_version()
        except ghexec.Blocked as exc:
            return self._refuse(R.AUT_TOOL_MISSING, f"BLOCKED: {exc}")
        except ghexec.GhExecError as exc:
            return self._refuse(R.AUT_TOOL_MISSING, str(exc))
        supported, code, detail = ghattest_parser.VERSION_GATE.check(gh_version)
        if not supported:
            return self._refuse(code, detail)

        try:
            result = ghexec.verify_attestation(
                artifact, repository=repository,
                bundle_path=config.resolve("gh", "attestationBundle"),
                trusted_root_path=config.resolve("gh", "attestationTrustedRoot"),
                digest_alg=digest_alg)
        except ghexec.Blocked as exc:
            return self._refuse(R.AUT_TOOL_MISSING, f"BLOCKED: {exc}")
        except ghexec.GhExecError as exc:
            return self._refuse(R.AUT_TOOL_MISSING, str(exc))
        if not result["verified"]:
            # gh's REAL exit code said no. Propagated verbatim, never softened.
            return self._refuse(R.AUT_SIGNATURE_INVALID,
                                f"gh REJECTED this attestation: {result['detail']}")

        parsed = ghattest_parser.parse_verify_output(result["stdout"],
                                                     gh_version=gh_version)
        if not parsed.ok:
            return self._refuse(parsed.reason_code, parsed.detail)
        record = parsed.data

        run_id = str(config.gh.get("runId") or "")
        check = ghattest_parser.check_against_subject(
            record, expected_repository=repository, expected_commit=commit,
            expected_artifact_digest=expected_digest, artifact_digest_alg=digest_alg,
            expected_run_id=run_id or None)
        if not check.ok:
            return self._refuse(check.reason_code, check.detail)

        if record["runnerEnvironment"] != "github-hosted":
            # gh was told --deny-self-hosted-runners; this re-checks the certificate's own
            # claim so a gh behaviour change cannot silently widen the boundary.
            return self._refuse(R.AUT_ENVIRONMENT_UNSUPPORTED,
                                f"the attestation was produced on a "
                                f"{record['runnerEnvironment']!r} runner; only "
                                f"github-hosted build environments are accepted here")

        fresh = ghattest_parser.freshness_from_record(
            record, config.freshness_max_age_seconds, now=int(time.time()))
        if not fresh.ok:
            return self._refuse(fresh.reason_code, fresh.detail)

        identity = {
            "kind": "gh-attestation-certificate",
            "sanUri": record["sanUri"],
            "subject": record["sanUri"],
            "issuer": record["issuer"],
            "repository": record["repository"],
            "workflowRef": record["workflowRef"],
            "runnerEnvironment": record["runnerEnvironment"],
            "ids": {"ownerId": record["ownerId"],
                    "repositoryId": record["repositoryId"]},
            "verifiedBy": "gh attestation verify",
        }
        binding = {
            "kind": "gh-artifact-attestation",
            "artifactDigest": expected_digest,
            "artifactDigestAlg": digest_alg,
            "artifactRehashedLocally": True,
            "commit": record["commit"],
            "repository": record["repository"],
            "repositoryId": record["repositoryId"],
            "runId": record["runId"],
            "runAttempt": record["runAttempt"],
            "predicateType": record["predicateType"],
            "attestationCount": record["attestationCount"],
            "mode": result["mode"],
            "ghVersion": gh_version,
            "binaryPath": result["binaryPath"],
            # Honesty about scope: this binds the ARTIFACT/commit/run, not the decision
            # digest. The decision references the artifact through its own subject; the
            # cosign path is what signs the decision digest itself.
            "bindsDecisionDigest": False,
        }
        return VerifierResult(
            verifier=self.name, verifier_version=f"gh {gh_version}", established=True,
            identity=identity, binding=binding, freshness=dict(fresh.data),
            detail=(f"gh attestation verify ({result['mode']}) exited 0 for the artifact "
                    f"this decision names ({digest_alg} {expected_digest[:16]}…, re-hashed "
                    f"locally), and the certificate names {record['repository']!r} @ "
                    f"{record['commit'][:12]} run {record['runId']}/"
                    f"{record['runAttempt']} — this decision's subject"),
        )


class GithubOidcIdentityVerifier(Verifier):
    """Identity: WHO ran the build, according to the external environment.

    In this release it ALWAYS refuses — see parsers/oidc.py. The refusal names which of the
    two blockers applies, so the operator learns something actionable rather than "no".
    """
    name = "github-oidc-identity"
    version = "github-actions-oidc/1"
    requires = (oidc_parser.SHAPE_CLAIMS, cosign_parser.SHAPE_BUNDLE_KEYLESS)

    def verify(self, decision, config):
        claims_path = config.resolve("oidc", "claims")
        if not claims_path:
            return self._refuse(
                R.AUT_IDENTITY_NOT_ESTABLISHED,
                "no external identity evidence is configured (oidc.claims). Identity may not "
                "be taken from a CLI argument, a repo file, an environment variable the target "
                "chose, or a git remote — all of those are written by the builder.")
        raw, err = _read(claims_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"OIDC claim set unreadable: {err}")

        pinned_issuer = config.oidc.get("expectedIssuer")
        if pinned_issuer is not None and pinned_issuer != oidc_parser.GITHUB_ISSUER:
            # Config may PIN the issuer; it may not WIDEN it to one this kit does not know.
            return self._refuse(
                R.AUT_IDENTITY_NOT_PERMITTED,
                f"oidc.expectedIssuer is {pinned_issuer!r}; this kit only knows "
                f"{oidc_parser.GITHUB_ISSUER!r} and will not accept a substitute trust root")

        claims_res = oidc_parser.parse_claims(raw)
        if not claims_res.ok:
            return self._refuse(claims_res.reason_code, claims_res.detail)

        claims = claims_res.data["claims"]
        repository, commit, mismatch = _subject_pins(decision, config)
        if mismatch:
            return self._refuse(R.AUT_BINDING_MISMATCH, mismatch)

        # LIVENESS IS NOT THIS VERIFIER'S JOB. A token has to have been live when it was
        # USED — i.e. at the moment Fulcio issued the certificate and Rekor logged the entry —
        # and only `CosignBundleVerifier` knows that moment. Judging a recorded claim set
        # against "now" would reject every archived token ever written, which is strictness
        # that means nothing. Passing the token's own `iat` reduces the check to internal
        # consistency (nbf <= iat < exp), which IS worth having.
        ok, code, detail = oidc_parser.check_claims(
            claims,
            expected_repository=repository,
            expected_sha=commit,
            expected_audience=config.oidc.get("expectedAudience"),
            at_time=claims.get("iat"))
        if not ok:
            return self._refuse(code, detail)

        # Everything checks out — and it is STILL not identity. This is the terminal answer
        # for the claim-set path, and `oidc.establishes_identity` is where it is written down.
        _, code, why = oidc_parser.establishes_identity(claims_res.data)
        context = oidc_parser.context_from_claims(claims)
        return self._refuse(code, f"{why} [claim context: {context}]")


class GithubEnvironmentPrincipalVerifier(Verifier):
    """Principal: did somebody the builder cannot impersonate have to act?

    THE ONLY SOURCE IS A LIVE OBSERVATION. This verifier used to read a JSON file whose path
    the operator supplied. An external audit showed what that meant: `principal` is the sole
    difference between CI_ATTESTED and INDEPENDENTLY_ATTESTED, so the product's strongest
    claim rested on a file written by the party seeking it, and six edits to a capture that
    ships inside the skill were enough to earn it.

    A file is therefore no longer a source, and no file format will be. `gh.environment`
    being set is now itself the refusal. The environment is read from api.github.com over
    TLS at verification time and the observation is bound to this decision's digest, or the
    principal is BLOCKED — see `authority/live.py`.

    The policy judgement is unchanged and still refuses the captured protected environment:
    self-review permitted, admins able to bypass, and no branch policy mean the environment
    constrains nobody. What changed is that satisfying that policy no longer proves anything
    about who said so.
    """
    name = "github-environment-principal"
    version = gh_parser.VERSION_GATE.describe()
    requires = (gh_parser.SHAPE_REPO, gh_parser.SHAPE_ENV, gh_parser.SHAPE_ENV_PROTECTED)

    def verify(self, decision, config):
        repo_path = config.resolve("gh", "repo")
        env_path = config.resolve("gh", "environment")
        # `gh.environment` is NO LONGER REQUIRED, and requiring it was a release blocker:
        # this guard demanded the file while `_observe` refuses when it is present, so every
        # configuration refused and the live branch could not be reached at all. What is
        # required now is the environment NAME, which says what to observe without asserting
        # what will be found.
        if not repo_path:
            return self._refuse(
                R.AUT_NOT_CONFIGURED,
                "gh.repo must be configured; an independent attestation needs the "
                "repository identity to establish which repository the environment "
                "belongs to")

        gh_version = config.gh.get("version")
        raw, err = _read(repo_path)
        if err:
            return self._refuse(R.AUT_TOOL_MISSING, f"gh repo output unreadable: {err}")
        repo_res = gh_parser.parse_repo(raw, gh_version=gh_version)
        if not repo_res.ok:
            return self._refuse(repo_res.reason_code, repo_res.detail)

        repository, _commit, mismatch = _subject_pins(decision, config)
        if mismatch:
            return self._refuse(R.AUT_BINDING_MISMATCH, mismatch)
        binding_res = gh_parser.check_repo_binding(repo_res.data, repository)
        if not binding_res.ok:
            return self._refuse(binding_res.reason_code, binding_res.detail)
        if repo_res.data["archived"]:
            return self._refuse(R.AUT_ENVIRONMENT_UNSUPPORTED,
                                "the subject repository is archived; its environments cannot "
                                "gate anything")

        # THE BLOCKING FINDING, CLOSED HERE.
        #
        # This used to read `gh.environment` off disk and, if the fields looked right,
        # establish `principal` — the fact that IS the difference between CI_ATTESTED and
        # INDEPENDENTLY_ATTESTED. An external audit pointed out that nothing proved the JSON
        # came from GitHub, and it was right: taking the shipped capture and flipping six
        # fields produced a passing independent principal.
        #
        # There is no shape a file can have that fixes this, so a file is no longer a source.
        # Either the verifier looked at GitHub itself or the fact is BLOCKED.
        observation = self._observe(config, decision, env_path)
        if isinstance(observation, VerifierResult):
            return observation
        env_res = gh_parser.parse_environment(
            json.dumps(observation["environment"]["body"]), gh_version=gh_version)
        if not env_res.ok:
            return self._refuse(env_res.reason_code, env_res.detail)

        wanted = config.gh.get("environmentName")
        if wanted and env_res.data["name"] != wanted:
            return self._refuse(R.AUT_BINDING_MISMATCH,
                                f"configured environment {wanted!r} but the record describes "
                                f"{env_res.data['name']!r}")

        corroboration = self._corroborate(config, env_res.data, gh_version)
        if isinstance(corroboration, VerifierResult):
            return corroboration

        # BUILDER IDS COME FROM THE LIVE RESPONSE, not from `gh.repo` on disk. Whether a
        # reviewer is a distinct principal depends on who the BUILDER can act as, so reading
        # the owner from an operator-supplied file let the operator understate their own
        # reach and make themselves look like a second party.
        live_repo = gh_parser.parse_repo(
            json.dumps(observation["repository"]["body"]),
            gh_version=gh_version)
        if not live_repo.ok:
            return self._refuse(live_repo.reason_code,
                                f"the LIVE repository response did not parse: "
                                f"{live_repo.detail}")
        qualifies, code, detail = gh_parser.is_qualifying_environment(
            env_res.data, builder_ids=self._builder_ids(config, live_repo.data))
        if not qualifies:
            return self._refuse(code, detail)

        deployment_record, deployment_note = self._deployment_evidence(observation)
        return VerifierResult(
            verifier=self.name, verifier_version=self.version, established=True,
            principal=dict(
                gh_parser.principal_from_environment(env_res.data, binding_res.data),
                corroboration=corroboration,
                # `authenticated` and `binding` are what `contracts.evaluate` requires before
                # it will award independence. They are set ONLY on this path — the one that
                # made a live observation — so a fabricated principal fact cannot carry them.
                authenticated=True,
                observedFrom=observation["environment"]["url"],
                observedAt=observation["observedAt"],
                # v4.2: PASSAGE evidence. None until the gh.run/deployments/statuses/
                # approvals shapes gain real captures — and `enforcement.enforce_award`
                # refuses independence (AUT_DEPLOYMENT_NOT_BOUND) while it is None, which
                # is exactly the fail-closed reading of "the gate exists but nothing shows
                # anyone passed through it".
                deployment=deployment_record,
                deploymentEvidence=deployment_note,
                binding=observation["binding"]),
            detail=(f"{detail} — observed live at "
                    f"{observation['environment']['url']} (HTTP "
                    f"{observation['environment']['httpStatus']}), bound to decision "
                    f"{observation['binding']['decisionDigest'][:16]}… "
                    f"[deployment evidence: {deployment_note['status']}]"),
        )

    def _deployment_evidence(self, observation):
        """(record_or_None, note). Fail closed, and say precisely which door is shut.

        The record may only come from shape-VALIDATED parses of the observed deployment
        parts. All four shapes are VALIDATED as of the 2026-08-08 field round, pinned to
        real captures, and the extraction below was written against those bytes. The
        honest outputs are therefore ABSENT (the parts were never observed), BLOCKED (a
        shape lost its capture or its digest moved) or OBSERVED (composed from validated
        parses). Judgement stays in enforcement.judge_deployment; this only extracts.
        """
        from . import shapes as shapes_module
        parts = ("run", "deployments", "deploymentStatuses", "approvals")
        observed = {name: observation.get(name) for name in parts}
        if not any(isinstance(v, dict) and "bodySha256" in v for v in observed.values()):
            return None, {
                "status": "ABSENT",
                "why": ("no deployment parts were observed — configure gh.runId so the "
                        "observer fetches the run, its deployments, their statuses and the "
                        "run's approvals alongside the environment")}
        shape_ids = ("gh.run.v1", "gh.deployments.v1", "gh.deployment.statuses.v1",
                     "gh.run.approvals.v1")
        reg = shapes_module.registry()
        blocked = [sid for sid in shape_ids
                   if reg.status(sid) != shapes_module.VALIDATED]
        if blocked:
            return None, {
                "status": "BLOCKED",
                "why": (f"deployment parts were observed but {', '.join(blocked)} have no "
                        f"real capture, so no validated shape exists to admit them; an "
                        f"unvalidated parse would be an optimistic interpretation and this "
                        f"kit does not make those. See SHAPES.json unblockProcedure."),
                "observedParts": sorted(n for n, v in observed.items()
                                        if isinstance(v, dict) and "bodySha256" in v)}
        # All four shapes are VALIDATED and the extraction below was written against their
        # REAL captures (2026-08-08; see SHAPES.json). The parse re-derives every part from
        # the BYTES the observer kept — `bodyB64` — not from the convenience `body` parse
        # beside them, because a digest over bytes nobody kept cannot be rechecked and the
        # two-phase path signs the digest, not the dict.
        import base64 as _b64

        def _bytes(part_name):
            part = observation.get(part_name)
            if not isinstance(part, dict):
                return None, f"the {part_name} part is absent from the observation"
            b64 = part.get("bodyB64")
            if not isinstance(b64, str) or not b64:
                return None, f"the {part_name} part kept no bytes to re-derive its parse from"
            try:
                raw = _b64.b64decode(b64, validate=True)
            except Exception as exc:
                return None, f"the {part_name} part's kept bytes are not valid base64: {exc}"
            recorded = part.get("bodySha256")
            got = hashlib.sha256(raw).hexdigest()
            if recorded and got != recorded:
                return None, (f"the {part_name} part's bytes do not match the digest recorded "
                              f"beside them (recorded {str(recorded)[:16]}…, got {got[:16]}…)")
            return raw, ""

        parsed = {}
        for part_name, parse in (("run", gh_parser.parse_run),
                                 ("deployments", gh_parser.parse_deployments),
                                 ("deploymentStatuses", gh_parser.parse_deployment_statuses),
                                 ("approvals", gh_parser.parse_run_approvals)):
            raw, problem = _bytes(part_name)
            if problem:
                return None, {"status": "BLOCKED", "why": problem}
            res = parse(raw)
            if not res.ok:
                return None, {"status": "BLOCKED",
                              "why": (f"the {part_name} part did not parse as its validated "
                                      f"shape: {res.reason_code}: {res.detail}")}
            parsed[part_name] = res.data

        # The protection facts come from the ENVIRONMENT record, which is observed on the
        # same authenticated pass. A run cannot assert its own gate's strictness.
        env_raw, problem = _bytes("environment")
        if problem:
            return None, {"status": "BLOCKED", "why": problem}
        env_res = gh_parser.parse_environment(env_raw)
        if not env_res.ok:
            return None, {"status": "BLOCKED",
                          "why": (f"the environment record did not parse as its validated "
                                  f"shape: {env_res.reason_code}: {env_res.detail}")}

        record, problem = gh_parser.compose_deployment_record(
            parsed["run"], parsed["deployments"], parsed["deploymentStatuses"],
            parsed["approvals"], env_res.data, env_res.data.get("name") or "")
        if problem:
            return None, {"status": "BLOCKED", "why": problem}
        return record, {
            "status": "OBSERVED",
            "why": ("deployment passage was extracted from shape-validated parses of the "
                    "observed run, deployments, statuses and approvals; judgement is "
                    "enforcement.judge_deployment, which this does not pre-empt"),
            "shapes": list(shape_ids),
            "deploymentId": record.get("deploymentId"),
            "environment": record.get("environment"),
            "builderSideIds": list(gh_parser.builder_side_ids(parsed["run"])),
            "observedParts": sorted(n for n, v in observed.items()
                                    if isinstance(v, dict) and "bodySha256" in v)}

    def _observe(self, config, decision, configured_path):
        """Make the live observation, or refuse. Never falls back to a file."""
        if configured_path:
            return self._refuse(
                R.AUT_PRINCIPAL_NOT_DISTINCT,
                "gh.environment names a FILE, and an operator-supplied environment record is "
                "no longer accepted as a principal: it is unauthenticated, nothing shows "
                "GitHub ever said it, and editing six fields of the shipped capture used to "
                "be enough to manufacture independence. The principal is observed live or it "
                "is BLOCKED. Remove gh.environment and set a verifier token; see "
                "`references/authority-kit.md`.")
        try:
            from . import live
        except ImportError as exc:  # pragma: no cover
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                f"the live observer is unavailable: {exc}")
        repository, _commit, mismatch = _subject_pins(decision, config)
        if mismatch:
            return self._refuse(R.AUT_BINDING_MISMATCH, mismatch)
        name = config.gh.get("environmentName")
        if not name:
            return self._refuse(R.AUT_NOT_CONFIGURED,
                                "gh.environmentName is required so the verifier knows which "
                                "environment to observe")
        run_id = str(config.gh.get("runId") or "")
        run_attempt = str(config.gh.get("runAttempt") or "")
        external_time = getattr(config, "external_time", None)

        recorded = config.resolve("verifier", "observation")
        if recorded:
            # TWO-PHASE. Phase 1 observed and wrote the result down; the verifier signed a
            # challenge that commits to the exact bytes GitHub returned. Loading it here is
            # not the unauthenticated file this kit refuses — editing any part of it changes
            # a digest the signature covers, so the signature check below is what makes it
            # admissible. This is the stronger of the two modes: the signature covers WHAT
            # was seen, not merely which release was vouched for.
            try:
                observation, challenge = live.load_observation(
                    recorded, decision, run_id, external_time, run_attempt)
            except live.LiveObservationError as exc:
                code = (R.AUT_BODY_DIGEST_MISMATCH if "BODY_DIGEST_MISMATCH" in str(exc)
                        else R.AUT_PRINCIPAL_NOT_DISTINCT)
                return self._refuse(code, str(exc))
            mode = "signed-replay"
        else:
            try:
                observation = live.observe_environment(
                    repository, name, fetch=config.gh.get("_fetch"),
                    run_id=run_id, commit=_commit)
            except live.Blocked as exc:
                return self._refuse(R.AUT_PRINCIPAL_NOT_DISTINCT, f"BLOCKED: {exc}")
            except live.LiveObservationError as exc:
                return self._refuse(R.AUT_PRINCIPAL_NOT_DISTINCT, str(exc))
            challenge = live.binding_challenge(observation, decision, run_id, external_time)
            mode = "live"
        who, verified, authorized, detail, policy_record = live.verify_verifier_identity(
            challenge,
            dict(getattr(config, "verifier", None) or {}, _repository=repository),
            resolve=lambda key: config.resolve("verifier", key))
        if not verified:
            return self._refuse(R.AUT_PRINCIPAL_NOT_DISTINCT, f"BLOCKED: {detail}")
        observation["binding"] = live.bind(
            observation, decision, external_time=external_time, run_id=run_id,
            run_attempt=run_attempt,
            verifier_identity=who, verifier_identity_verified=True,
            verifier_authorized=authorized, policy=policy_record)
        observation["verifierDetail"] = detail
        observation["binding"]["observationMode"] = mode
        observation["binding"]["challengeCovers"] = (
            "decision, commit, run, AND the observed response-body digests"
            if mode == "signed-replay" else
            "decision, commit and run only — the response bodies are NOT signed")
        return observation

    def _builder_ids(self, config, repo_data):
        """Principals the BUILDER can already act as, so a reviewer who is one of them does
        not count as distinct.

        Two sources, both external: the repository owner when the owner is a User (a
        user-owned repo's owner can always push to it), and the OIDC `actor_id` — who
        actually triggered the run — when a claim set is configured. An organisation owner id
        is deliberately NOT included: an org is not a person and a reviewing team inside it
        can be genuinely separate.
        """
        ids = set()
        owner = (repo_data or {}).get("owner") or {}
        if owner.get("type") == "User" and owner.get("id") is not None:
            ids.add(str(owner["id"]))
        claims_path = config.resolve("oidc", "claims")
        if claims_path:
            raw, err = _read(claims_path)
            if not err:
                parsed = oidc_parser.parse_claims(raw)
                if parsed.ok:
                    actor = parsed.data["claims"].get("actor_id")
                    if actor is not None:
                        ids.add(str(actor))
        return tuple(sorted(ids))

    def _corroborate(self, config, env_record, gh_version):
        """Optional cross-checks: the environment LIST and the environment's SECRETS.

        The list check catches an environment record that does not belong to this repository's
        set. The secrets read exists because "how much does this environment actually hold" is
        part of judging it — and because zero secrets must parse as zero, not as an error.
        """
        notes = {}
        list_path = config.resolve("gh", "environmentList")
        if list_path:
            raw, err = _read(list_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING,
                                    f"gh environment list unreadable: {err}")
            list_res = gh_parser.parse_environment_list(raw, gh_version=gh_version)
            if not list_res.ok:
                return self._refuse(list_res.reason_code, list_res.detail)
            ids = [e["id"] for e in list_res.data["environments"]]
            if env_record["id"] not in ids:
                return self._refuse(
                    R.AUT_BINDING_MISMATCH,
                    f"environment {env_record['name']!r} (id {env_record['id']}) is not in "
                    f"this repository's environment list {ids}")
            notes["environmentList"] = {"totalCount": list_res.data["totalCount"]}

        secrets_path = config.resolve("gh", "environmentSecrets")
        if secrets_path:
            raw, err = _read(secrets_path)
            if err:
                return self._refuse(R.AUT_TOOL_MISSING,
                                    f"gh environment secrets unreadable: {err}")
            sec_res = gh_parser.parse_environment_secrets(raw, gh_version=gh_version)
            if not sec_res.ok:
                return self._refuse(sec_res.reason_code, sec_res.detail)
            notes["environmentSecrets"] = {"totalCount": sec_res.data["totalCount"],
                                           "empty": sec_res.data["empty"]}
        return notes


__all__ = [
    "CosignBundleVerifier", "GhAttestationVerifier", "GithubEnvironmentPrincipalVerifier",
    "GithubOidcIdentityVerifier", "RekorTransparencyVerifier",
]
