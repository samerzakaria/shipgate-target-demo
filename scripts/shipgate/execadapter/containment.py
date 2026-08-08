"""Containment detection — PROVED, not presumed.

v3.8 decided a boundary existed from `shutil.which(...)`. That is how a run ends up
believing it is sandboxed while every target process runs on the host: the binary is
present, the namespace operation is denied by the kernel (unprivileged userns disabled,
seccomp, a nested container), and nothing notices.

Here every candidate boundary must survive a live probe before it counts, and the probe
asserts the property that matters:

  container : engine runs, image resolves, and a probe container starts as a non-root uid
  bwrap     : a probe process actually starts under bwrap with the requested namespaces
              AND cannot write to a path that was bound read-only
  unshare   : recorded as HARDENING ONLY. `unshare -Umn` gives network and mount namespaces
              but leaves the whole host filesystem writable at the caller's uid, so it does
              not confine target code. It is never an accepted boundary; it is applied on
              top of another boundary's absence purely to remove network egress, and the
              containment record says so.

Probe results are cached per process — the answer cannot change mid-run, and re-probing per
command would add a container start to every subprocess.
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

#: Kinds that genuinely confine target-controlled code.
REAL_BOUNDARIES = ("container", "bwrap")
#: Kinds that reduce blast radius but do NOT confine. Never accepted as containment.
HARDENING_ONLY = ("unshare",)

_PROBE_TIMEOUT = 25
_cache = {}


class ContainmentUnavailable(RuntimeError):
    """Required containment could not be established. ALWAYS fatal — there is no fallback.

    Raised before any target-controlled process is spawned, so a refusal never leaves a
    half-run behind.
    """

    def __init__(self, message, detail=None):
        super().__init__(message)
        self.detail = detail or {}


def _run(argv, timeout=_PROBE_TIMEOUT, env=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _probe_container():
    """(ok, detail). Requires an engine, an explicitly configured image, and a container
    that actually starts as a non-root uid."""
    engine = shutil.which("docker") or shutil.which("podman")
    image = (os.environ.get("SHIPGATE_RUNNER_IMAGE") or "").strip()
    if not engine:
        return False, {"reason": "no docker/podman on PATH"}
    if not image:
        return False, {"reason": "SHIPGATE_RUNNER_IMAGE is not set",
                       "engine": os.path.basename(engine)}
    r = _run([engine, "run", "--rm", "--network=none", "--cap-drop=ALL",
              "--security-opt", "no-new-privileges", "--user", "1000:1000",
              image, "sh", "-c", "id -u"])
    if r is None or r.returncode != 0:
        return False, {"reason": "probe container did not start",
                       "engine": os.path.basename(engine), "image": image,
                       "stderr": (r.stderr or "")[:400] if r else "probe failed to spawn"}
    uid = (r.stdout or "").strip()
    if uid in ("", "0"):
        return False, {"reason": f"probe container ran as uid {uid or 'unknown'!r}, expected non-root",
                       "engine": os.path.basename(engine), "image": image}
    return True, {"engine": os.path.basename(engine), "image": image, "probeUid": uid}


def _probe_bwrap():
    """(ok, detail). Starts a probe under bwrap and asserts a read-only bind really is
    read-only — a bwrap that silently degrades is not a boundary."""
    engine = shutil.which("bwrap")
    if not engine:
        return False, {"reason": "bwrap not on PATH"}
    with tempfile.TemporaryDirectory(prefix="shipgate-bwrap-probe-") as tmp:
        ro = Path(tmp) / "ro"
        ro.mkdir()
        (ro / "canary").write_text("x", encoding="utf-8")
        script = f'if echo tampered > {ro}/canary 2>/dev/null; then echo WRITABLE; else echo READONLY; fi'
        r = _run([engine, "--unshare-all", "--die-with-parent",
                  "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                  "--ro-bind", str(ro), str(ro),
                  "--chdir", tmp, "/bin/sh", "-c", script])
        if r is None or r.returncode != 0:
            return False, {"reason": "bwrap probe did not run (namespaces likely denied)",
                           "stderr": (r.stderr or "")[:400] if r else "probe failed to spawn"}
        verdict = (r.stdout or "").strip()
        if verdict != "READONLY":
            return False, {"reason": f"bwrap read-only bind was {verdict or 'inconclusive'}"}
        if (ro / "canary").read_text(encoding="utf-8") != "x":
            return False, {"reason": "bwrap read-only bind leaked a write to the host"}
    return True, {"engine": "bwrap"}


def _probe_unshare():
    engine = shutil.which("unshare")
    if not engine:
        return False, {"reason": "unshare not on PATH"}
    r = _run([engine, "-Umn", "--", "/bin/sh", "-c", "echo ok"])
    if r is None or r.returncode != 0 or "ok" not in (r.stdout or ""):
        return False, {"reason": "unshare probe did not run (unprivileged userns likely disabled)"}
    return True, {"engine": "unshare",
                  "caveat": "network+mount namespace only; host filesystem remains writable"}


_PROBES = {
    "container": _probe_container,
    "bwrap": _probe_bwrap,
    "unshare": _probe_unshare,
}


def probe(kind, force=False):
    """(ok, detail) for one candidate, cached."""
    if kind not in _PROBES:
        return False, {"reason": f"unknown containment kind {kind!r}"}
    if force or kind not in _cache:
        _cache[kind] = _PROBES[kind]()
    return _cache[kind]


def reset_cache():
    _cache.clear()


def detect(accepted=REAL_BOUNDARIES, force=False):
    """Determine the boundary in force.

    Returns a record used verbatim in the decision's `containment` block:

        {"kind": <str>, "established": bool, "accepted": [...], "candidates": {...},
         "hardening": [...], "detail": {...}}

    `kind` is "none" when nothing accepted was proved. `established` is True ONLY for a
    proved, accepted boundary — it is never True because a binary exists.
    """
    requested = (os.environ.get("SHIPGATE_EXEC_MODE") or "auto").strip().lower()
    order = [k for k in ("container", "bwrap") if k in accepted]
    if requested == "container":
        order = [k for k in order if k == "container"]
    elif requested == "bwrap":
        order = [k for k in order if k == "bwrap"]
    elif requested == "none":
        order = []

    candidates = {}
    chosen, chosen_detail = "none", {}
    for kind in order:
        ok, detail = probe(kind, force=force)
        candidates[kind] = {"available": ok, **detail}
        if ok and chosen == "none":
            chosen, chosen_detail = kind, detail

    hardening = []
    if chosen == "none":
        ok, detail = probe("unshare", force=force)
        candidates["unshare"] = {"available": ok, **detail}
        if ok:
            hardening.append("unshare")

    return {
        "kind": chosen,
        "established": chosen in REAL_BOUNDARIES,
        "requested": requested,
        "accepted": list(accepted),
        "candidates": candidates,
        "hardening": hardening,
        "detail": chosen_detail,
    }


def describe(record):
    if record["established"]:
        d = record.get("detail") or {}
        if record["kind"] == "container":
            return f"container ({d.get('engine', '?')} / {d.get('image', '?')}), non-root, no network"
        return "bwrap (network denied; host filesystem read-only except the run area)"
    if record.get("hardening"):
        return ("NO containment boundary. unshare is present but gives no filesystem "
                "confinement — hardening only.")
    return "NO containment boundary available."
