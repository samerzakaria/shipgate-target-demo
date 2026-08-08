"""Single source of truth for release / schema identity. Stdlib only, no internal imports."""

SKILL_NAME = "ship-gate"
SKILL_VERSION = "4.2.2"

# Identity stamped into every decision so a consumer can tell WHICH engine produced it.
ENGINE_ID = f"{SKILL_NAME}/{SKILL_VERSION}"

# Versioned contracts. Bump independently of SKILL_VERSION when the shape changes.
DECISION_SCHEMA_VERSION = "shipgate.decision/1"
PROFILE_SCHEMA_VERSION = "shipgate.profile/1"
EVIDENCE_SCHEMA_VERSION = "shipgate.evidence/1"
ATTESTATION_SCHEMA_VERSION = "shipgate.attestation/1"

# The execution environments this release is DECLARED to support and is TESTED on.
# Anything not listed here is unsupported and must be reported honestly, never silently.
SUPPORTED_PLATFORMS = ("linux-x86_64",)
