"""Safe collector-evidence caching.

`CachePolicy` was modelled and never consulted. Wiring it is only defensible if a cache hit is
INDISTINGUISHABLE from a fresh run, so the rules here are deliberately strict — a gate that
reuses a stale observation is a gate that reports on a build that no longer exists.

THE FIVE RULES

  1. KEYED BY INPUT DIGEST, NOT BY NAME. The key covers the collector's identity AND version,
     the tree digest, the commit, the artifact digest and the collector options. Change any
     one and the key changes, so a hit can only ever occur for byte-identical inputs.
  2. ONLY COMPLETE OBSERVATIONS ARE STORED. `ERROR`, `ABSENT` and `PARTIAL` evidence is never
     written. A transient tool failure must not become sticky — that would turn one bad run
     into a permanently red gate, and worse, an operator would "fix" it by clearing a cache
     rather than by fixing the tool.
  3. PER-RUN KINDS ARE NEVER CACHED. Containment describes THIS process's boundary. Findings
     and the workspace describe THIS round. Caching any of them would let one run's
     containment record vouch for another's.
  4. AGE IS JUDGED ON THE REAL CLOCK. `SHIPGATE_SOURCE_DATE_EPOCH` cannot make a stale entry
     look fresh, for the same reason it cannot make stale evidence look fresh.
  5. AN UNREADABLE OR MISMATCHED ENTRY IS A MISS, NEVER AN ERROR. The cache is an optimisation;
     it may never change an outcome. If anything at all looks wrong, the collector runs.

Depends on: shipgate.models, shipgate.util, stdlib.
"""
import os
from pathlib import Path
from typing import Optional

from ..models.evidence import Evidence, EvidenceBinding, EvidenceKind, EvidenceStatus
from ..util.canonical import canonical_bytes, digest_of, loads_strict
from ..util.clock import age_seconds, utcnow_iso

CACHE_SCHEMA = "shipgate.evidence-cache/1"

#: Kinds whose meaning is bound to THIS process or THIS round. Never cached, at any age.
NEVER_CACHE = frozenset({
    EvidenceKind.CONTAINMENT,   # describes this process's proved boundary
    EvidenceKind.FINDINGS,      # describes this round
    EvidenceKind.WORKSPACE,     # describes this run area's creation
})


class EvidenceCache:
    """A content-addressed store for complete collector observations.

    Disabled by default. When disabled every method is a no-op returning `None`, so callers
    need no conditional.
    """

    def __init__(self, policy, binding, options=None, run_area=None):
        self.enabled = bool(getattr(policy, "enabled", False))
        self.max_age = int(getattr(policy, "max_age_seconds", 3600) or 3600)
        self.binding = binding
        self.options = dict(options or {})
        self.hits = []
        self.misses = []
        self.stores = []
        self.refusals = []

        directory = getattr(policy, "directory", None)
        if self.enabled and not directory and run_area:
            directory = str(Path(run_area) / "shipgate-workdir" / "cache")
        self.directory = Path(directory).resolve() if directory else None
        if self.enabled and self.directory:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # A cache we cannot create is a cache we do not use. Never fatal.
                self.enabled = False
                self.refusals.append(f"cache disabled: cannot create {self.directory}: {exc}")

    # --- keying -------------------------------------------------------------------------
    def key_for(self, collector):
        """The content address. Everything that could change the observation is in here."""
        return digest_of({
            "schema": CACHE_SCHEMA,
            "collector": collector.name,
            "collectorVersion": collector.version,
            "kind": collector.kind.value,
            "repository": self.binding.repository,
            "commit": self.binding.commit,
            "treeDigest": self.binding.tree_digest,
            "artifactDigest": self.binding.artifact_digest,
            "options": {k: v for k, v in sorted(self.options.items())
                        if isinstance(v, (str, int, bool, type(None)))},
        })

    def _path(self, key):
        return self.directory / f"{key}.json"

    # --- read ---------------------------------------------------------------------------
    def get(self, collector):
        """Return cached Evidence, or None. Any doubt at all resolves to None."""
        if not self.enabled or self.directory is None:
            return None
        if collector.kind in NEVER_CACHE:
            self.refusals.append(f"{collector.kind.value}: never cached (per-run evidence)")
            return None

        key = self.key_for(collector)
        path = self._path(key)
        if not path.exists():
            self.misses.append({"kind": collector.kind.value, "key": key})
            return None

        try:
            doc = loads_strict(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            self.refusals.append(f"{collector.kind.value}: unreadable entry ({exc})")
            return None

        problem = self._reject(doc, collector, key)
        if problem:
            self.refusals.append(f"{collector.kind.value}: {problem}")
            return None

        ev = _rehydrate(doc["evidence"])
        if ev is None:
            self.refusals.append(f"{collector.kind.value}: entry did not rehydrate")
            return None
        self.hits.append({"kind": collector.kind.value, "key": key,
                          "storedAt": doc.get("storedAt")})
        return ev

    def _reject(self, doc, collector, key):
        """Reason to refuse this entry, or None to accept it."""
        if not isinstance(doc, dict):
            return "entry is not an object"
        if doc.get("schema") != CACHE_SCHEMA:
            return f"schema {doc.get('schema')!r} is not {CACHE_SCHEMA!r}"
        if doc.get("key") != key:
            return "stored key does not match the recomputed key"

        age = age_seconds(doc.get("storedAt"))
        if age is None:
            return f"unreadable storedAt {doc.get('storedAt')!r}"
        if age < 0:
            return "entry is dated in the future"
        if age > self.max_age:
            return f"entry is {age}s old, over the {self.max_age}s limit"

        ev = doc.get("evidence")
        if not isinstance(ev, dict):
            return "entry carries no evidence object"
        if ev.get("status") != EvidenceStatus.COLLECTED.value:
            return f"stored status {ev.get('status')!r} is not COLLECTED"
        if ev.get("kind") != collector.kind.value:
            return f"stored kind {ev.get('kind')!r} is not {collector.kind.value!r}"

        b = ev.get("binding") or {}
        for field, want in (("repository", self.binding.repository),
                            ("commit", self.binding.commit),
                            ("treeDigest", self.binding.tree_digest),
                            ("artifactDigest", self.binding.artifact_digest)):
            if want is not None and b.get(field) != want:
                return f"binding {field} {b.get(field)!r} != {want!r}"
        return None

    # --- write --------------------------------------------------------------------------
    def put(self, collector, evidence):
        """Store a COMPLETE observation. Silently declines anything else."""
        if not self.enabled or self.directory is None:
            return False
        if collector.kind in NEVER_CACHE:
            return False
        if evidence is None or evidence.status is not EvidenceStatus.COLLECTED:
            return False
        if evidence.uncovered:
            return False   # PARTIAL coverage must be re-attempted, not frozen

        key = self.key_for(collector)
        body = {
            "schema": CACHE_SCHEMA,
            "key": key,
            "storedAt": utcnow_iso(),
            "evidence": evidence.to_json(),
        }
        try:
            tmp = self._path(key).with_suffix(".tmp")
            tmp.write_bytes(canonical_bytes(body))
            os.replace(tmp, self._path(key))   # atomic; a torn write is never readable
        except OSError as exc:
            self.refusals.append(f"{collector.kind.value}: could not store ({exc})")
            return False
        self.stores.append({"kind": collector.kind.value, "key": key})
        return True

    # --- reporting ----------------------------------------------------------------------
    def summary(self):
        """Recorded in the run log so a cache hit is always visible, never invisible."""
        return {
            "enabled": self.enabled,
            "directory": str(self.directory) if self.directory else None,
            "maxAgeSeconds": self.max_age,
            "hits": len(self.hits),
            "misses": len(self.misses),
            "stores": len(self.stores),
            "refusals": list(self.refusals),
            "hitKinds": sorted({h["kind"] for h in self.hits}),
        }


def _rehydrate(body):
    """Rebuild Evidence from its JSON. Returns None if anything is off."""
    try:
        b = body["binding"]
        binding = EvidenceBinding(
            run_id=b["runId"], round_index=int(b["round"]), repository=b["repository"],
            commit=b["commit"], tree_digest=b["treeDigest"],
            artifact_id=b.get("artifactId"), artifact_digest=b.get("artifactDigest"))
        return Evidence(
            kind=EvidenceKind(body["kind"]),
            collector=body["collector"],
            collector_version=body["collectorVersion"],
            status=EvidenceStatus(body["status"]),
            binding=binding,
            collected_at=body["collectedAt"],
            payload=body.get("payload") or {},
            note=body.get("note", ""),
            uncovered=tuple(body.get("uncovered") or ()),
            schema=body.get("schema", ""),
        )
    except (KeyError, ValueError, TypeError):
        return None
