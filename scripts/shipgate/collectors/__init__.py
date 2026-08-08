"""Collectors — the OBSERVING half of the gate.

A collector reads the run area, or drives a process through the execution adapter, and
returns typed `Evidence`. It never decides, never raises past `Collector.run`, and never
returns a clean-looking payload for something it could not observe.

Dependency rules (enforced by tests/boundary/):
  * MAY import: shipgate.models, shipgate.util, shipgate.execadapter, stdlib.
  * MUST NOT import: shipgate.authority, shipgate.semantic, or any OIDC / signing /
    attestation / Rekor / policy-server / promotion / independent-verifier code.
  * MUST NOT import `subprocess` — every process goes through `ctx.adapter`.

`ALL_COLLECTORS` is the declaration order AND the execution order. The ordering is
load-bearing:
  * WorkspaceCollector first — nothing else may touch the tree before isolation is recorded.
  * The seals are taken BEFORE any fault injection, so the baseline is the pristine tree.
  * FailFirstCollector after FaultAuditCollector (it reads the audit's fault records).
  * CujCollector after RuntimeProbeCollector (it reconciles journeys against probe results).
  * DesignConformanceCollector and CrossSurfaceCollector after UiCrawlCollector — both read
    the census it captured rather than driving the browser a second time against a live
    target. They are read-only over that artifact, so they are parallel-safe.
  * RequirementsCollector after CujCollector and LedgerCollector: it resolves every
    requirement link against the ids those two actually produced, so running it earlier would
    report every link dangling — the honest result, and a useless one.
  * AdversarialProbeCollector after CujCollector — the procedure's own Phase H rule is
    "close D–F first": attacking a system you have not evidenced produces findings nobody
    can localise, and it corrupts the CUJ evidence you were about to rely on.
  * LedgerCollector second to last — it reconciles the declared capability surface against
    every runtime observation. Run it earlier and every capability is UNVERIFIED, which
    fails the ledger check: the honest result, never a silent pass.
  * FindingsCollector last — it summarises what everything else raised.
"""
from . import base, cache, scheduler
from .base import Collector, CollectorContext, run_all
from .cache import EvidenceCache
from .scheduler import (
    SchedulingError, describe as describe_plan, run_scheduled)
from .adversarial import AdversarialProbeCollector
from .conformance import CrossSurfaceCollector, DesignConformanceCollector
from .requirements import RequirementsCollector
from .crawl import A11yCollector, PerfCollector, UiCrawlCollector
from .cuj import CujCollector
from .envfault import EnvFaultCollector
from .faults import FailFirstCollector, FaultAuditCollector
from .findings import FindingsCollector
from .heldout import HeldOutCollector
from .ledger import LedgerCollector
from .mutation import MutationCollector
from .probe import RuntimeProbeCollector
from .security import SecurityCollector
from .specseal import SpecSealCollector
from .stack import StackCollector
from .testseal import TestSealCollector
from .workspace import WorkspaceCollector

ALL_COLLECTORS = (
    WorkspaceCollector,
    StackCollector,
    TestSealCollector,
    SpecSealCollector,
    RuntimeProbeCollector,
    UiCrawlCollector,
    A11yCollector,
    PerfCollector,
    SecurityCollector,
    FaultAuditCollector,
    FailFirstCollector,
    MutationCollector,
    HeldOutCollector,
    EnvFaultCollector,
    CujCollector,
    AdversarialProbeCollector,
    DesignConformanceCollector,
    CrossSurfaceCollector,
    LedgerCollector,
    RequirementsCollector,
    FindingsCollector,
)

#: Cheap, read-only collectors that never execute target code. Used by `--dry-run` and by
#: the packaging self-test, which must not build or boot a target application.
STATIC_COLLECTORS = (
    WorkspaceCollector,
    StackCollector,
    TestSealCollector,
    SpecSealCollector,
    FindingsCollector,
)

__all__ = [
    "base", "cache", "scheduler", "Collector", "CollectorContext", "run_all",
    "EvidenceCache", "run_scheduled", "describe_plan", "SchedulingError",
    "ALL_COLLECTORS", "STATIC_COLLECTORS",
    "A11yCollector", "CujCollector", "EnvFaultCollector", "FailFirstCollector",
    "FaultAuditCollector", "FindingsCollector", "HeldOutCollector", "LedgerCollector",
    "AdversarialProbeCollector", "CrossSurfaceCollector",
    "DesignConformanceCollector", "MutationCollector", "PerfCollector",
    "RequirementsCollector", "RuntimeProbeCollector", "SecurityCollector",
    "SpecSealCollector", "StackCollector", "TestSealCollector", "UiCrawlCollector",
    "WorkspaceCollector",
]
