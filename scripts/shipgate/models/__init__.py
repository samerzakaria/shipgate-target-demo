"""Typed domain models. This package imports ONLY from `shipgate.util` and the stdlib.

It must never import collectors, semantic, decision-building, reporting, or authority code —
that is what makes it safe for every other layer to depend on it.
"""
from . import coverage, reasons
from .decision import (
    Attestation,
    AttestedDecision,
    CheckResult,
    CujOutcome,
    Decision,
    EXIT_CODES,
    HeldOutOutcome,
    Outcome,
    ProvenanceStatus,
    SemanticStatus,
    SubjectIdentity,
    ThresholdResult,
    derive_outcome,
)
from .coverage import (
    AGENTIC_PHASES,
    PHASES,
    PhaseClaim,
    PhaseCoverage,
    TRUST_SELF_ATTESTED,
    build as build_coverage,
)
from .evidence import (
    Evidence,
    EvidenceBinding,
    EvidenceKind,
    EvidenceSet,
    EvidenceStatus,
)
from .finding import BLOCKING, Finding, FindingState, NON_WAIVABLE, Severity, blocking_findings, summarise
from .policy import BreakGlass, CachePolicy, ContainmentPolicy, Mode, Policy
from .profile import (
    BUILTIN as BUILTIN_PROFILES,
    CheckSpec,
    Comparison,
    DEEP,
    DEFAULT_PROFILE_ID,
    EscalationSignal,
    Profile,
    ProfileResolution,
    STANDARD,
    Threshold,
    get as get_profile,
    resolve as resolve_profile,
)

__all__ = [
    "coverage", "reasons",
    "Attestation", "AttestedDecision", "CheckResult", "CujOutcome", "Decision", "EXIT_CODES",
    "HeldOutOutcome", "Outcome", "ProvenanceStatus", "SemanticStatus", "SubjectIdentity",
    "ThresholdResult", "derive_outcome",
    "AGENTIC_PHASES", "PHASES", "PhaseClaim", "PhaseCoverage",
    "TRUST_SELF_ATTESTED", "build_coverage",
    "Evidence", "EvidenceBinding", "EvidenceKind", "EvidenceSet", "EvidenceStatus",
    "BLOCKING", "Finding", "FindingState", "NON_WAIVABLE", "Severity", "blocking_findings",
    "summarise",
    "BreakGlass", "CachePolicy", "ContainmentPolicy", "Mode", "Policy",
    "BUILTIN_PROFILES", "CheckSpec", "Comparison", "DEEP", "DEFAULT_PROFILE_ID",
    "EscalationSignal", "Profile", "ProfileResolution", "STANDARD", "Threshold",
    "get_profile", "resolve_profile",
]
