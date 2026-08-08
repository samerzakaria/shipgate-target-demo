"""Output-shape parsers. Machine-readable input only, fail-closed on everything else.

Imports: shipgate.models, shipgate.util, shipgate.authority.shapes, stdlib. Nothing else —
in particular no subprocess and no network IN THIS PACKAGE: these parse bytes handed to
them. Execution lives in ../cosignexec.py and observation in ../live.py, one level up.
"""
from . import cosign, gh, oidc, rekor
from ._common import ParseResult, VersionGate

__all__ = ["ParseResult", "VersionGate", "cosign", "gh", "oidc", "rekor"]
