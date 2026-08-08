"""ship-gate v4.0 — library API.

Layering (one-way dependency flow, enforced by tests/boundary/test_import_boundary.py):

    util        ->  (nothing internal)
    models      ->  util
    execadapter ->  models, util
    collectors  ->  models, util, execadapter
    semantic    ->  models, util, collectors
    reporting   ->  models, util
    runner      ->  models, util, execadapter, collectors, semantic
    authority   ->  models, util, execadapter        (OPTIONAL, physically removable)

Every layer may additionally import `shipgate.version`, which is a leaf holding release and
schema identity only. The table above is the one `tests/boundary/test_import_boundary.py`
enforces; if the two ever disagree, the test is right and this docstring is wrong.

`semantic`, `collectors`, `decision` and `reporting` MUST NOT import `shipgate.authority`
or any OIDC / signing / attestation / Rekor / policy-server / promotion / independent-verifier
module. The VERIFIED workflow is fully functional when `shipgate/authority/` is deleted.

Public entry points:
    shipgate.run_semantic_gate(...)   -> models.decision.Decision   (never needs authority)
    shipgate.authority_status()       -> AuthorityAvailability       (safe when authority absent)
"""
from .version import (
    SKILL_NAME,
    SKILL_VERSION,
    ENGINE_ID,
    DECISION_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSION,
)

__all__ = [
    "SKILL_NAME",
    "SKILL_VERSION",
    "ENGINE_ID",
    "DECISION_SCHEMA_VERSION",
    "PROFILE_SCHEMA_VERSION",
    "run_semantic_gate",
    "authority_status",
    "AUTHORITY_PACKAGE",
]

AUTHORITY_PACKAGE = "shipgate.authority"


def run_semantic_gate(*args, **kwargs):
    """Lazy re-export of the semantic engine entry point (keeps import cost off `import shipgate`)."""
    from .semantic.engine import run_semantic_gate as _run
    return _run(*args, **kwargs)


def authority_status():
    """Probe for the OPTIONAL authority kit WITHOUT importing it into the semantic path.

    Returns a plain dict: {"present": bool, "reason": str}. Callers above the decision
    boundary (gate.py) use this to decide whether to attempt attestation. The semantic
    core never calls it.
    """
    import importlib.util
    try:
        spec = importlib.util.find_spec(AUTHORITY_PACKAGE)
    except (ImportError, ValueError, ModuleNotFoundError):
        spec = None
    if spec is None:
        return {"present": False, "reason": "AUTHORITY_KIT_ABSENT"}
    return {"present": True, "reason": "AUTHORITY_KIT_PRESENT"}
