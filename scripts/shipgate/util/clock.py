"""Time handling.

Every timestamp in a decision is UTC, second-resolution, RFC3339 with a literal 'Z'.
Sub-second precision is deliberately dropped: it is pure entropy in a digest and makes
otherwise-identical decisions differ.

SHIPGATE_SOURCE_DATE_EPOCH pins `utcnow_iso()` for reproducibility tests. It is honoured
ONLY for the decision timestamp field and never for freshness arithmetic — see
`age_seconds`, which always uses the real clock, so a pinned build clock can never make
stale evidence look fresh.
"""
import datetime as _dt
import os

_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _real_now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def utcnow_iso():
    pin = (os.environ.get("SHIPGATE_SOURCE_DATE_EPOCH") or "").strip()
    if pin:
        try:
            return _dt.datetime.fromtimestamp(int(pin), _dt.timezone.utc).strftime(_FMT)
        except (ValueError, OSError, OverflowError):
            pass
    return _real_now().strftime(_FMT)


def parse_iso(text):
    """Parse an RFC3339 UTC timestamp. Returns None on anything we cannot read exactly.

    Callers MUST treat None as 'unparseable evidence' and fail closed — never as 'now'.
    """
    if not isinstance(text, str) or not text:
        return None
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None  # naive timestamps are ambiguous; refuse rather than assume UTC
    return dt.astimezone(_dt.timezone.utc)


def age_seconds(text, now=None):
    """Age of a timestamp in seconds against the REAL clock. None if unparseable.

    A negative age (timestamp in the future) is returned as-is so the caller can reject it;
    clamping to 0 would silently accept a forward-dated artifact.
    """
    dt = parse_iso(text)
    if dt is None:
        return None
    ref = now or _real_now()
    return int((ref - dt).total_seconds())
