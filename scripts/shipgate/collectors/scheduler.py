"""Dependency-aware, bounded-concurrency collector scheduling.

WHY THIS EXISTS, AND WHY IT IS CAREFUL

`Policy.parallelism` was recorded and never acted on. Making it real is not simply a matter
of throwing collectors at a thread pool, because the collector order in v4.0 is *load-bearing*
in three separate ways:

  1. SOME COLLECTORS MUTATE THE TREE. The fault auditor injects a syntax-level fault, runs the
     suite, and reverts. The mutation runner rewrites source. The env-fault operator rewrites
     configuration. Two of those running at once corrupt each other's baseline and the result
     is not merely slow — it is WRONG, and wrong in the direction of a false pass, because a
     fault reverted by the wrong collector looks like a fault that was detected.
  2. SOME COLLECTORS FEED OTHERS. Stack detection populates `ctx.stack`. The probe writes
     `probe.json`, which the CUJ collector and the ledger reconcile against. The fault audit
     writes the fault records the fail-first collector reads.
  3. THE SEALS MUST PRECEDE MUTATION. A test seal taken after a fault was injected seals the
     faulted tree.

So concurrency here is OPT-IN PER COLLECTOR and DEPENDENCY-ORDERED. A collector is treated as
unsafe to parallelise unless it explicitly declares otherwise — the fail-closed default, since
the cost of being wrong is a corrupted run rather than a slow one.

DETERMINISM IS NON-NEGOTIABLE

The decision digest must not depend on how many workers ran. Results are therefore collected
into a map and inserted into the `EvidenceSet` in DECLARATION order, never completion order.
`tests/integration/test_parallel_determinism.py` asserts that parallelism 1 and parallelism 8
produce byte-identical decisions over the same fixture.

Depends on: shipgate.models, shipgate.util, stdlib. No subprocess (collectors own that, via the
execution adapter).
"""
import concurrent.futures
import threading
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models.evidence import Evidence, EvidenceKind, EvidenceStatus

#: Collectors that WRITE to the run area. These never run concurrently — not with each other
#: and not with anything else. Membership is by evidence kind so it survives class renames.
#:
#: This list is deliberately generous. A read-only collector wrongly listed here costs a little
#: wall-clock; a mutating collector wrongly omitted corrupts a run.
TREE_MUTATING_KINDS = frozenset({
    EvidenceKind.FAULT_AUDIT,    # injects and reverts source faults
    EvidenceKind.FAIL_FIRST,     # injects a fault per candidate test
    EvidenceKind.MUTATION,       # rewrites source, writes reports into the tree
    EvidenceKind.ENV_FAULT,      # rewrites environment/config for the target
    EvidenceKind.HELDOUT,        # restores the vault into the tree, runs, clears
    EvidenceKind.WORKSPACE,      # creates the run area and hides scaffolding
    EvidenceKind.TEST_SEAL,      # writes the seal
    EvidenceKind.SPEC_SEAL,      # writes the spec baseline
})

#: Collectors that only READ, and may therefore share the run area with each other. A
#: collector must be listed here to be eligible for concurrency; anything unlisted is serial.
PARALLEL_SAFE_KINDS = frozenset({
    EvidenceKind.STACK,
    EvidenceKind.SECURITY,
    EvidenceKind.ACCESSIBILITY,
    EvidenceKind.PERFORMANCE,
    EvidenceKind.UI_CRAWL,
    #: Both read the census the UI crawl already wrote to disk. They execute nothing, drive
    #: nothing and touch no target state, so they may share a wave with each other and with
    #: the other read-only crawl consumers.
    EvidenceKind.DESIGN_CONFORMANCE,
    EvidenceKind.CROSS_SURFACE,
    #: Reads the manifest and the artifacts other collectors already wrote. Read-only.
    EvidenceKind.REQUIREMENTS,
})

#: Collectors that do not rewrite source, but still may not share the run area — because they
#: drive the LIVE SYSTEM or because they reconcile what everything else produced. Serial by
#: DECISION, not by falling through a default.
#:
#: The distinction from TREE_MUTATING_KINDS is about what would break: a second fault injector
#: corrupts the tree, whereas a second prober corrupts the *application's* state. Both are
#: unsafe; only the first is a filesystem problem.
STATEFUL_KINDS = frozenset({
    #: Boots and exercises the running application, and may issue write-method probes. Two
    #: probers against one app race on the app's own state, not on the tree.
    EvidenceKind.RUNTIME_PROBE,
    #: Drives whole journeys — log in, create, pay. State-changing by definition.
    EvidenceKind.CUJ,
    #: Sends deliberately hostile requests to the live application, including malformed
    #: write bodies. It is the LEAST safe collector to run beside another prober: half its
    #: oracle is "did this request return a DIFFERENT identity's data", and a concurrent
    #: collector mutating the same records could manufacture or mask exactly that.
    EvidenceKind.ADVERSARIAL_PROBE,
    #: The reconciliation step. Reads every runtime observation and merges them into the
    #: capability ledger; running it beside a collector still producing observations would
    #: reconcile against a moving target.
    EvidenceKind.LEDGER,
    #: Summarises what every other collector raised, so it is last by construction.
    EvidenceKind.FINDINGS,
})

#: Every collector kind must appear in exactly one of the three sets. `test_parallel_
#: determinism.py` asserts total coverage, which is what turns "serial" from an accident into
#: a decision — the first version of this module left four kinds unclassified and they were
#: serial only because the default happened to be safe.
CLASSIFIED_KINDS = TREE_MUTATING_KINDS | PARALLEL_SAFE_KINDS | STATEFUL_KINDS

#: kind -> kinds that must have completed first.
DEPENDENCIES: Dict[EvidenceKind, Tuple[EvidenceKind, ...]] = {
    EvidenceKind.STACK: (EvidenceKind.WORKSPACE,),
    EvidenceKind.TEST_SEAL: (EvidenceKind.WORKSPACE,),
    EvidenceKind.SPEC_SEAL: (EvidenceKind.WORKSPACE,),
    EvidenceKind.RUNTIME_PROBE: (EvidenceKind.STACK,),
    EvidenceKind.UI_CRAWL: (EvidenceKind.STACK, EvidenceKind.RUNTIME_PROBE),
    EvidenceKind.ACCESSIBILITY: (EvidenceKind.UI_CRAWL,),
    EvidenceKind.PERFORMANCE: (EvidenceKind.UI_CRAWL,),
    EvidenceKind.SECURITY: (EvidenceKind.STACK,),
    # The seals must be taken on the PRISTINE tree, before anything injects a fault.
    EvidenceKind.FAULT_AUDIT: (EvidenceKind.STACK, EvidenceKind.TEST_SEAL,
                               EvidenceKind.SPEC_SEAL),
    EvidenceKind.FAIL_FIRST: (EvidenceKind.FAULT_AUDIT,),
    EvidenceKind.MUTATION: (EvidenceKind.FAULT_AUDIT,),
    EvidenceKind.HELDOUT: (EvidenceKind.TEST_SEAL,),
    EvidenceKind.ENV_FAULT: (EvidenceKind.RUNTIME_PROBE,),
    EvidenceKind.CUJ: (EvidenceKind.RUNTIME_PROBE,),
    # Attack a system you have already evidenced — the procedure's own rule (Phase H
    # step 1). Attacking an unevidenced system produces findings nobody can localise.
    EvidenceKind.ADVERSARIAL_PROBE: (EvidenceKind.RUNTIME_PROBE, EvidenceKind.CUJ),
    EvidenceKind.LEDGER: (EvidenceKind.RUNTIME_PROBE, EvidenceKind.CUJ),
    # Both read `crawl.json`, which the UI crawl writes.
    EvidenceKind.DESIGN_CONFORMANCE: (EvidenceKind.UI_CRAWL,),
    EvidenceKind.CROSS_SURFACE: (EvidenceKind.UI_CRAWL,),
    # Resolves every requirement link against the ids the CUJ, probe and ledger collectors
    # actually produced. Running it earlier would report every link dangling — honest, and
    # useless.
    EvidenceKind.REQUIREMENTS: (EvidenceKind.CUJ, EvidenceKind.LEDGER,
                                EvidenceKind.RUNTIME_PROBE),
    EvidenceKind.FINDINGS: (),   # runs last by declaration order, reads the workdir
}


class SchedulingError(RuntimeError):
    """The collector set cannot be ordered. Always a programming error, never a run outcome."""


def is_parallel_safe(kind):
    """Fail closed: only an explicitly listed read-only kind may share a wave.

    An unclassified kind is serial. That default is safe, but it is not a substitute for
    classifying — see CLASSIFIED_KINDS and the test that enforces total coverage.
    """
    if kind in TREE_MUTATING_KINDS or kind in STATEFUL_KINDS:
        return False
    return kind in PARALLEL_SAFE_KINDS


def plan(collectors):
    """Group collectors into ordered WAVES.

    Every collector in a wave may run concurrently with the others in it; waves run strictly
    in sequence, and a serial collector always gets a wave to itself.

    TWO RULES, and the second one is the subtle one:

      (a) A collector runs only once its declared DEPENDENCIES have completed.
      (b) A collector runs only once every EARLIER-DECLARED SERIAL collector has completed.

    Rule (b) exists because dependency edges alone are not the whole story. The declaration
    order in `ALL_COLLECTORS` encodes sequencing the author intended but did not write down as
    an edge: findings summarise what everything else raised, and the held-out suite should not
    restore its vault into the tree before the probe has observed the running system. Without
    (b), a scheduler that only honours explicit edges happily runs FINDINGS in wave 5 — which
    is exactly what the first version of this function did, because FINDINGS declares no
    dependencies at all.

    Read-only collectors that sit next to each other in the declaration order still batch, so
    the concurrency that matters is preserved.
    """
    collectors = list(collectors)
    present = {c.kind for c in collectors}
    index = {id(c): i for i, c in enumerate(collectors)}
    remaining = list(collectors)
    done = set()
    waves = []
    guard = 0

    def deps_met(c):
        return all(d in done or d not in present for d in DEPENDENCIES.get(c.kind, ()))

    while remaining:
        guard += 1
        if guard > len(collectors) + 2:
            raise SchedulingError(
                f"dependency cycle or unsatisfiable dependency among "
                f"{[c.kind.value for c in remaining]}")

        # Rule (b): the earliest not-yet-run SERIAL collector is a barrier.
        barrier = None
        for c in remaining:
            if not is_parallel_safe(c.kind):
                barrier = index[id(c)]
                break

        ready = [c for c in remaining
                 if deps_met(c) and (barrier is None or index[id(c)] <= barrier)]
        if not ready:
            raise SchedulingError(
                f"no collector is runnable; unresolved: "
                f"{[c.kind.value for c in remaining]}. The earliest serial collector is "
                f"blocked on a dependency that never completes.")

        # Whatever was DECLARED EARLIEST among the ready set goes first. Picking the serial
        # collector whenever one happened to be ready let a later-declared mutating collector
        # jump ahead of earlier-declared read-only ones — which reordered the run relative to
        # what the author wrote, and pushed the crawl and the security scan to the very end.
        earliest = min(ready, key=lambda c: index[id(c)])
        if not is_parallel_safe(earliest.kind):
            wave = [earliest]
        else:
            serial_idx = [index[id(c)] for c in ready if not is_parallel_safe(c.kind)]
            cut = min(serial_idx) if serial_idx else len(collectors) + 1
            wave = sorted((c for c in ready
                           if is_parallel_safe(c.kind) and index[id(c)] < cut),
                          key=lambda c: index[id(c)])

        waves.append(wave)
        for c in wave:
            done.add(c.kind)
            remaining.remove(c)
    return waves


def run_scheduled(collectors, ctx, evidence_set, parallelism=1, on_wave=None):
    """Run collectors respecting dependencies, with bounded concurrency.

    `parallelism <= 1` degrades to the exact sequential behaviour of `base.run_all`, which is
    what keeps the default path unchanged.

    Evidence is appended to `evidence_set` in DECLARATION order regardless of how the work was
    scheduled, so the resulting decision is identical at any parallelism.
    """
    collectors = list(collectors)
    workers = max(1, int(parallelism))
    waves = plan(collectors)
    results: Dict[int, Evidence] = {}
    index = {id(c): i for i, c in enumerate(collectors)}
    stack_lock = threading.Lock()

    def _run_one(collector):
        ev = collector.run(ctx)
        # Stack evidence feeds every later collector; publish it under a lock so a concurrent
        # reader never sees a half-assigned dict.
        if collector.kind is EvidenceKind.STACK and ev.status is EvidenceStatus.COLLECTED:
            with stack_lock:
                ctx.stack = ev.payload
        return ev

    for wave_no, wave in enumerate(waves, 1):
        started = time.monotonic()
        if workers == 1 or len(wave) == 1:
            for c in wave:
                # The SAME guard as the concurrent path. The first version only guarded the
                # thread-pool branch, so a collector that raised past its own handler took the
                # whole run down whenever parallelism was 1 — i.e. on the default path.
                try:
                    results[index[id(c)]] = _run_one(c)
                except Exception as exc:  # noqa: BLE001
                    results[index[id(c)]] = Evidence.error(
                        c.kind, c.name, c.version, ctx.binding,
                        note=f"collector raised past its own guard: "
                             f"{type(exc).__name__}: {exc}")
        else:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(workers, len(wave)),
                    thread_name_prefix="shipgate-collector") as pool:
                futures = {pool.submit(_run_one, c): c for c in wave}
                for fut in concurrent.futures.as_completed(futures):
                    c = futures[fut]
                    # `Collector.run` never raises, but a scheduler that assumed so and was
                    # wrong would lose evidence silently. Convert anything that escapes.
                    try:
                        results[index[id(c)]] = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        results[index[id(c)]] = Evidence.error(
                            c.kind, c.name, c.version, ctx.binding,
                            note=f"collector raised past its own guard: "
                                 f"{type(exc).__name__}: {exc}")
        if on_wave is not None:
            on_wave(wave_no, [c.kind.value for c in wave],
                    int((time.monotonic() - started) * 1000))

    for i in range(len(collectors)):
        if i in results:
            evidence_set.add(results[i])
    return evidence_set


def describe(collectors, parallelism=1):
    """Human-readable plan, for `gate.py doctor` and the run log."""
    waves = plan(list(collectors))
    lines = [f"collector plan: {len(collectors)} collectors in {len(waves)} waves "
             f"at parallelism {max(1, int(parallelism))}"]
    for i, wave in enumerate(waves, 1):
        mode = "concurrent" if len(wave) > 1 and parallelism > 1 else "serial"
        lines.append(f"  wave {i:2d} [{mode:10s}] " +
                     ", ".join(c.kind.value for c in wave))
    return "\n".join(lines)
