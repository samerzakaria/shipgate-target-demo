"""Collector contract.

A collector OBSERVES and returns `Evidence`. It does not decide, does not raise on a
finding, and does not know what a profile is. Anything it cannot determine becomes an
`ERROR`/`PARTIAL` evidence — never a silent success and never a default-pass.

Every collector receives the shared `ExecutionAdapter`; none may import `subprocess`.
`tests/boundary/test_no_direct_subprocess.py` enforces that by AST scan.
"""
import abc
import traceback

from ..models.evidence import Evidence, EvidenceKind, EvidenceStatus


class CollectorContext:
    """Everything a collector is allowed to know about the run."""

    def __init__(self, repo, run_area, workdir, binding, adapter, stack=None, options=None):
        self.repo = repo                # the user's original tree (READ ONLY)
        self.run_area = run_area        # the isolated copy/worktree the gate operates on
        self.workdir = workdir          # shipgate-workdir inside the run area
        self.binding = binding          # models.evidence.EvidenceBinding
        self.adapter = adapter          # execadapter.ExecutionAdapter — the ONLY exec path
        self.stack = stack or {}        # detected stack, populated after the stack collector
        self.options = dict(options or {})

    def option(self, name, default=None):
        return self.options.get(name, default)


class Collector(abc.ABC):
    """Base class. Subclasses implement `collect` and declare `kind`/`name`/`version`."""

    kind: EvidenceKind = None
    name: str = ""
    version: str = "4.2.2"
    #: When False, `run` returns ABSENT evidence instead of calling `collect`.
    applicable_always: bool = True

    @abc.abstractmethod
    def collect(self, ctx):
        """Return an `Evidence`. May raise; `run` converts an exception to ERROR evidence."""

    def applicable(self, ctx):
        return self.applicable_always

    # --- driver ------------------------------------------------------------------------
    def run(self, ctx):
        """Never raises. A crashing collector yields ERROR evidence, which the engine treats
        as a failure when the evidence is required — a crash can never look like a pass."""
        if not self.applicable(ctx):
            return Evidence.absent(self.kind, self.name, self.version, ctx.binding,
                                   note="not applicable to the detected stack/profile")
        try:
            ev = self.collect(ctx)
        except Exception as exc:  # noqa: BLE001 — deliberate: any failure becomes evidence
            return Evidence.error(
                self.kind, self.name, self.version, ctx.binding,
                note=f"{type(exc).__name__}: {exc}",
                payload={"traceback": traceback.format_exc(limit=8)})
        if not isinstance(ev, Evidence):
            return Evidence.error(
                self.kind, self.name, self.version, ctx.binding,
                note=f"collector returned {type(ev).__name__}, expected Evidence")
        if ev.kind is not self.kind:
            return Evidence.error(
                self.kind, self.name, self.version, ctx.binding,
                note=f"collector returned evidence of kind {ev.kind.value}, expected {self.kind.value}")
        return ev

    # --- helpers ------------------------------------------------------------------------
    def collected(self, ctx, payload, note="", uncovered=()):
        return Evidence.collected(self.kind, self.name, self.version, ctx.binding,
                                  payload, note=note, uncovered=uncovered)

    def error(self, ctx, note, payload=None):
        return Evidence.error(self.kind, self.name, self.version, ctx.binding, note, payload)

    def absent(self, ctx, note=""):
        return Evidence.absent(self.kind, self.name, self.version, ctx.binding, note)


def run_all(collectors, ctx, evidence_set):
    """Run collectors in declaration order, feeding the detected stack forward."""
    for c in collectors:
        ev = c.run(ctx)
        evidence_set.add(ev)
        if c.kind is EvidenceKind.STACK and ev.status is EvidenceStatus.COLLECTED:
            ctx.stack = ev.payload
    return evidence_set
