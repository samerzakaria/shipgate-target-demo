SYNTHETIC-ADVERSARIAL FIXTURES — NOT CAPTURES. NOT EVIDENCE.
============================================================

Every file in this directory was HAND-AUTHORED by the ship-gate v4.0 authority-kit build to
exercise parser branches for output shapes that could NOT be captured from a real tool. They
are deliberately, permanently distinguishable from the real corpus:

  * filename prefix `SYNTHETIC-ADVERSARIAL__` — `fixtures.synthetic()` REFUSES to load a file
    without it, and refuses to look in captures/ at all;
  * `shapes.ShapeRegistry` will only mark a shape VALIDATED from `captures/normalized/` with
    provenance REAL_CAPTURE, so nothing here can ever be promoted to evidence;
  * the corresponding shapes are BLOCKED in schemas/SHAPES.json.

UPDATED 2026-08-05, second capture round. Real captures arrived for the OIDC claim set, a
keyless cosign bundle and a protected GitHub environment, so two of these files no longer
test a REFUSAL — they now exercise the POSITIVE branch of a predicate whose shape has been
validated. That is a legitimate use for a labelled synthetic input (it is a test vector for
`is_qualifying_environment` / `parse_claims`, not evidence about anybody's build), and it
changes nothing about the rule that a synthetic file can never validate a shape.

Files
-----
SYNTHETIC-ADVERSARIAL__cosign_bundle_keyless.json
    A KEYLESS SIGSTORE BUNDLE v0.3 skeleton (verificationMaterial.certificate instead of
    .publicKey). STILL A REFUSAL TEST: the real keyless capture that arrived turned out to be
    the LEGACY cosign serialisation ({base64Signature, cert, rekorBundle}), which is a
    different shape, so `cosign.bundle.keyless.v0_3` remains BLOCKED and this file must keep
    being refused with AUT_OUTPUT_SHAPE_UNKNOWN.

SYNTHETIC-ADVERSARIAL__gh_env_protected.json
    A GitHub environment that satisfies every independence requirement: a required_reviewers
    rule with a reviewer, prevent_self_review true, can_admins_bypass false, and a deployment
    branch policy. NOW EXPECTED TO QUALIFY — `is_qualifying_environment` returns True for it,
    which is how the predicate's positive branch is exercised. The REAL protected capture
    (captures/normalized/env_protected_one.json) does NOT qualify: it has
    prevent_self_review false, can_admins_bypass true and a null branch policy.

SYNTHETIC-ADVERSARIAL__oidc_claims.json
    A GitHub Actions OIDC claim set. NOW EXPECTED TO PARSE, because the shape is validated.
    It still establishes NO identity — `oidc.establishes_identity()` returns False for every
    input, because this kit cannot verify a JWT signature. It is also used to check that a
    wrong audience and a foreign repository claim are refused with their own reason codes.

To replace one with a REAL capture, follow `unblockProcedure` in schemas/SHAPES.json. Never
move a file from this directory into captures/.

REAL-FIXTURE__ — real inputs, still not captures (added 2026-08-07, v4.2)
-------------------------------------------------------------------------
Three files with the REAL-FIXTURE__ prefix are INPUTS for the gh attestation-verify
positive control, not tool output and not synthetic:

REAL-FIXTURE__npm_sigstore_verify_4.1.2.tgz
    The real npm package @sigstore/verify@4.1.2 tarball, byte-identical to what
    registry.npmjs.org serves (sha512 05f0fd78baf3dc0f...). The attested ARTIFACT.

REAL-FIXTURE__npm_sigstore_verify_4.1.2.sigstore.json
    The real SLSA-provenance Sigstore bundle for that package, produced by
    sigstore/sigstore-js's release workflow on GitHub Actions and served by the npm
    registry's attestations endpoint. GitHub-produced, not authored here.

REAL-FIXTURE__sigstore_trusted_root.jsonl
    The Sigstore TUF trusted root as fetched by `gh attestation trusted-root` on
    2026-08-07. Lets `gh attestation verify` run fully OFFLINE in the suite.

Why here and not captures/: the corpus holds what TOOLS PRINTED; these are what a tool is
GIVEN. The integration tests run the REAL gh binary over these three files and judge its
real exit code — that is the reachable positive control for the gh adapter, and it needs no
network and no token. See captures PROVENANCE_gh_attestation.txt for the full procedure.
