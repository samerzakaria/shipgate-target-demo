"""Axis B — the semantic core.

Depends on: shipgate.models, shipgate.util, shipgate.collectors (for kind constants only),
stdlib. It MUST NOT import shipgate.authority or any OIDC / signing / attestation / Rekor /
policy-server / promotion / independent-verifier module.
"""
from .checks import EvalContext, REGISTRY as CHECK_REGISTRY, evaluator
from .engine import SemanticEngineError, run_semantic_gate
from .evidence_gate import validate as validate_evidence

__all__ = [
    "EvalContext", "CHECK_REGISTRY", "evaluator",
    "SemanticEngineError", "run_semantic_gate", "validate_evidence",
]
