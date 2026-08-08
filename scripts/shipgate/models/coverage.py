"""Phase coverage — what the OPERATING AGENT says it did, kept strictly weaker than evidence.

THE PROBLEM THIS EXISTS FOR. Most of the gate is collectors: deterministic programs that
observe a running system and hand back typed evidence. Four phases of the written procedure
are not, because they are judgement — A2 (deriving requirements from the BRD/HLD/design
system), G2 (design-system and visual conformance), G3 (cross-surface consistency) and H
(the adversarial round). Nothing in the engine recorded whether the agent performed them.
In a behaviour evaluation an agent reached VERIFIED without running Phase H, then ran it on
request and found a broken object-level authorisation bug and an unhandled 500 in about two
minutes. VERIFIED was emitted over a live authz bypass because a non-mechanical phase was
skipped, and the decision said nothing about it.

WHY THE OBVIOUS FIX IS FORBIDDEN. The obvious fix — require a phase record and block
VERIFIED without it — is ruled out by this system's own rule that self-attested evidence is
strictly weaker than collected evidence and may never raise a status. A blocking gate on a
self-reported field would make the strongest outcome in the product contingent on the least
trustworthy input in it, and would hand the graded agent a one-line incantation that clears
the gate. That is a reward hack wearing a compliance badge.

THE ASYMMETRY THIS MODULE IS BUILT ON. A POSITIVE self-report ("H ran and passed") is
untrustworthy and can never raise confidence. A NEGATIVE self-report ("H not run") is
against interest and is safe to act on. So the invariant is:

    SELF-ATTESTED COVERAGE MAY ONLY EVER SUBTRACT FROM DISPLAYED CONFIDENCE.

Three consequences are structural rather than advisory, and `tests/negative/` asserts each:

  * SILENCE DEFAULTS TO `not_run`. An omitted claim is treated as the conservative value,
    so there is no incentive to say nothing.
  * A CLAIM NEVER REACHES CLEAN. `run` moves a phase from "not run" to "self-reported,
    not collected" — which is still a caveat. Only COLLECTED evidence removes one. The
    vocabulary has no code for "coverage complete"; the unsafe direction is unsayable.
  * THE BLOCK IS NOT EVIDENCE. It lives beside `evidence` in the decision, not inside it,
    and every element carries `trustClass: "self_attested"` — the same enum value Axis A
    uses for the weakest provenance — so code that already refuses to let self-attestation
    raise a status refuses here for free.

WHAT REMOVES A CAVEAT. Exactly one thing: a collector. Phase H now has one — the
ADVERSARIAL_PROBE collector mechanises the falsifiable core of the adversarial round (the
ID-coercion differential and the malformed-input property) under the same fail-first
admission rule the rest of the kit uses. When that evidence is COLLECTED and its check
passes, H's caveat is gone, because the claim is no longer what is being trusted. A2, G2
and G3 have no collector and therefore always carry a caveat: that is the honest state, and
saying so is the whole point.
"""
import dataclasses
from typing import Any, Dict, Optional, Tuple

from . import reasons as R

#: The trust class every element of this block carries. Deliberately the SAME string Axis A
#: uses for its weakest state, so that a reader — or a code path — that already knows what
#: `self_attested` means does not have to learn a second, parallel vocabulary.
TRUST_SELF_ATTESTED = "self_attested"
TRUST_COLLECTED = "collected"

#: Every phase of the written procedure, in order.
PHASES = ("0", "A", "A2", "B", "C", "D", "E", "F", "G", "G2", "G3", "H", "I", "J")

#: The phases no collector observes. These are the only ones a claim is meaningful about;
#: a claim about, say, Phase D is ignored, because Phase D has evidence and evidence wins.
AGENTIC_PHASES = ("A2", "G2", "G3", "H")

#: What each agentic phase is, for the report. Short on purpose — the reader wants to know
#: what was skipped, not to re-read the procedure.
PHASE_TITLES = {
    "A2": "requirements depth: BRD/HLD/design-system/wireframes read and turned into "
          "numbered, risk-ranked conditions",
    "G2": "exploratory pass: design-system and visual conformance across viewports",
    "G3": "domain behavioural invariants: money and permissions, cross-surface consistency",
    "H": "adversarial round: spec-derived hostile inputs against the live system",
}

#: The phase whose absence caused the incident. Kept as a name because a good deal of prose
#: and several tests point at it.
CORROBORATED_PHASE = "H"

#: The phases a COLLECTOR can establish, and the only set `--require-coverage` may name.
#:
#: All four now have one. Each collector mechanises the FALSIFIABLE FLOOR of its phase and
#: nothing above it: whether the requirements manifest hangs together and cites every source
#: (A2), whether the rendered UI uses the declared design tokens (G2), whether surfaces agree
#: with each other (G3), whether a coerced id or a hostile body gets through (H). None of
#: them grades judgement, and `describe()` on each says so in the output of `gate.py doctor`.
#:
#: The restriction on `--require-coverage` remains the point. A phase with no collector could
#: only be "satisfied" by an agent saying it ran, which inverts the rule this module exists
#: to hold. The set is now four rather than one because four collectors were built, not
#: because the rule was relaxed.
COLLECTOR_BACKED_PHASES = ("A2", "G2", "G3", "H")

CLAIM_RUN = "run"
CLAIM_NOT_RUN = "not_run"
CLAIMS = (CLAIM_RUN, CLAIM_NOT_RUN)

#: How much a caveat weighs, for ordering in the report. Not a severity — nothing here
#: fails anything — just the order a reader should see them in.
_WEIGHT = {"H": 0, "G3": 1, "A2": 2, "G2": 3}


class CoverageError(ValueError):
    """A phase record is malformed. Fatal to the record, never to the run: the runner
    turns it into the conservative record (everything `not_run`) rather than dropping the
    block, because dropping it would make a malformed claim look like no claim at all."""


@dataclasses.dataclass(frozen=True)
class PhaseClaim:
    """One agentic phase, as the agent described it. Never as anything else described it."""
    phase: str
    claim: str = CLAIM_NOT_RUN
    detail: str = ""
    #: Set by the ENGINE, never by the agent. True only when a collector corroborated the
    #: phase. An agent-supplied value for this field is discarded on construction.
    corroborated: bool = False

    def to_json(self):
        return {
            "phase": self.phase,
            "claim": self.claim,
            "trustClass": TRUST_COLLECTED if self.corroborated else TRUST_SELF_ATTESTED,
            "corroborated": self.corroborated,
            "detail": self.detail,
            "title": PHASE_TITLES.get(self.phase, ""),
        }


@dataclasses.dataclass(frozen=True)
class PhaseCoverage:
    """The self-attested coverage block, plus whatever a collector corroborated.

    Construct through `build`. The constructor is not the safe entry point: `build` is
    where silence becomes `not_run` and where an agent-supplied `corroborated` is thrown
    away, and skipping it would skip the two rules that make the block safe.
    """
    claims: Tuple[PhaseClaim, ...] = ()
    source: str = "operating_agent"
    #: Free text from the agent about the record as a whole. Never parsed.
    note: str = ""

    # --- derived ----------------------------------------------------------------------
    def claim_for(self, phase) -> Optional[PhaseClaim]:
        for c in self.claims:
            if c.phase == phase:
                return c
        return None

    def declared_not_run(self) -> Tuple[str, ...]:
        return tuple(c.phase for c in self.claims if c.claim != CLAIM_RUN
                     and not c.corroborated)

    def uncorroborated_claims(self) -> Tuple[str, ...]:
        return tuple(c.phase for c in self.claims
                     if c.claim == CLAIM_RUN and not c.corroborated)

    def corroborated(self) -> Tuple[str, ...]:
        return tuple(c.phase for c in self.claims if c.corroborated)

    def complete(self) -> bool:
        """True only when EVERY agentic phase was corroborated by a collector.

        Unreachable from self-report alone, and that is the design. Today only Phase H has
        a collector, so this returns False on every real run — which is the honest answer,
        not a bug to be smoothed over.
        """
        return bool(self.claims) and all(c.corroborated for c in self.claims)

    def caveats(self) -> Tuple[Dict[str, Any], ...]:
        """The subtractions. Ordered most-important first; never empty unless complete."""
        out = []
        for c in sorted(self.claims, key=lambda x: (_WEIGHT.get(x.phase, 9), x.phase)):
            if c.corroborated:
                continue
            if c.claim == CLAIM_RUN:
                out.append({
                    "phase": c.phase,
                    "state": "SELF_REPORTED_NOT_COLLECTED",
                    "trustClass": TRUST_SELF_ATTESTED,
                    "reasonCode": R.COV_PHASE_CLAIM_UNCORROBORATED,
                    "summary": (f"phase {c.phase} is self-reported as run; no collector "
                                f"corroborates it"),
                    "title": PHASE_TITLES.get(c.phase, ""),
                })
            else:
                out.append({
                    "phase": c.phase,
                    "state": "NOT_RUN",
                    "trustClass": TRUST_SELF_ATTESTED,
                    "reasonCode": (R.COV_ADVERSARIAL_NOT_COLLECTED
                                   if c.phase == CORROBORATED_PHASE else R.COV_PHASE_NOT_RUN),
                    "summary": f"phase {c.phase} was not run",
                    "title": PHASE_TITLES.get(c.phase, ""),
                })
        return tuple(out)

    def reason_codes(self) -> Tuple[str, ...]:
        """Informational codes for the decision. None of them is in SEMANTIC_FAILING."""
        if self.complete():
            return ()
        codes = [R.COV_PARTIAL_SELF_DECLARED]
        for cav in self.caveats():
            code = cav["reasonCode"]
            if code not in codes:
                codes.append(code)
        return tuple(codes)

    def display_suffix(self) -> str:
        """What to append to the outcome string. Empty when nothing is caveated.

        This is the only place coverage touches how an outcome READS, and it can only ever
        add a qualification. `Outcome` itself, and the exit code derived from it, are
        untouched — a caveat is not a failure and must not be reported as one.
        """
        cavs = self.caveats()
        if not cavs:
            return ""
        not_run = [c["phase"] for c in cavs if c["state"] == "NOT_RUN"]
        reported = [c["phase"] for c in cavs if c["state"] == "SELF_REPORTED_NOT_COLLECTED"]
        parts = []
        if not_run:
            parts.append(f"{'/'.join(not_run)} not run")
        if reported:
            parts.append(f"{'/'.join(reported)} self-reported")
        return "partial coverage (" + "; ".join(parts) + ")"

    def to_json(self):
        return {
            "schema": "shipgate.coverage/1",
            "source": self.source,
            #: The block-level trust class. Present even when some phases were corroborated,
            #: because the RECORD is still an agent's account of itself; corroboration is
            #: recorded per phase, where it can be checked.
            "trustClass": TRUST_SELF_ATTESTED,
            "note": self.note,
            "phases": [c.to_json() for c in
                       sorted(self.claims, key=lambda x: (_WEIGHT.get(x.phase, 9), x.phase))],
            "declaredNotRun": list(self.declared_not_run()),
            "uncorroboratedClaims": list(self.uncorroborated_claims()),
            "corroborated": list(self.corroborated()),
            "coverageComplete": self.complete(),
            "caveats": [dict(c) for c in self.caveats()],
            "reasonCodes": list(self.reason_codes()),
        }


def build(claims=None, source="operating_agent", note="", corroborated=()) -> PhaseCoverage:
    """The only safe way to make a `PhaseCoverage`.

    `claims` maps phase -> "run" | "not_run" | {"claim": ..., "detail": ...}. Anything the
    agent supplies that is not one of the two claim words is read as `not_run`: an
    unparseable claim is not a claim, and guessing in the permissive direction is exactly
    the mistake this module exists to avoid.

    `corroborated` is the set of phases a COLLECTOR established. It is supplied by the
    runner from evidence, never by the agent, and it is the only input that can clear a
    caveat.
    """
    raw = dict(claims or {})
    corroborated = {str(p) for p in corroborated}
    out = []
    for phase in AGENTIC_PHASES:
        entry = raw.get(phase)
        claim, detail = CLAIM_NOT_RUN, ""
        if isinstance(entry, str):
            claim = entry.strip().lower()
        elif isinstance(entry, dict):
            claim = str(entry.get("claim", "")).strip().lower()
            d = entry.get("detail")
            detail = d.strip() if isinstance(d, str) else ""
        elif entry is True:
            # Tolerated because a JSON author will write it, and rejecting the record
            # outright would lose the OTHER phases' claims. Read as the claim it means.
            claim = CLAIM_RUN
        elif entry is False:
            claim = CLAIM_NOT_RUN
        if claim not in CLAIMS:
            claim = CLAIM_NOT_RUN
        out.append(PhaseClaim(phase=phase, claim=claim, detail=detail[:400],
                              corroborated=phase in corroborated))
    return PhaseCoverage(claims=tuple(out), source=str(source or "operating_agent")[:120],
                         note=str(note or "")[:400])


def parse_phase_list(text) -> Dict[str, str]:
    """`"A2,H"` -> {"A2": "run", ...}. Unknown or non-agentic names are ignored, not errors.

    A phase name the gate does not track is not a coverage claim about anything, and
    failing the run over one would turn a reporting convenience into a blocker.
    """
    claims = {}
    for part in str(text or "").replace(";", ",").split(","):
        name = part.strip().upper()
        if name in AGENTIC_PHASES:
            claims[name] = CLAIM_RUN
    return claims


#: The conservative record: nothing claimed, nothing corroborated. What a run that supplied
#: no phase information gets — identical to a run that explicitly said it did none of them,
#: which is the point of defaulting on silence.
def empty() -> PhaseCoverage:
    return build()
