"""ENV_FAULT collector — the faults that actually break login.

Ported from v3.8 `envfault.py`. Source-code fault injection perturbs handler files; the class
that produces "green CI, dead login" is not a source bug — it is a wrong build-time env var, a
rotated signing secret, a wrong OAuth callback host, a skipped migration or a dependency being
down. None of those is a regex over a handler file.

Preserved verbatim in behaviour:

  * OPERATOR PLANNING FROM REAL ENV KEYS: `.env.example` plus every `process.env.X` /
    `process.env["X"]` / `os.environ[...]` / `os.getenv(...)` reference in source, so the plan
    covers keys the code READS even when the template omits them (itself a finding);
  * the classification order — `_HOSTY` BEFORE `_SECRETY`, because `OAUTH_CALLBACK_URL`
    matches both and its login-breaking fault is a WRONG HOST, not a rotated secret;
  * the operator set: env-missing / env-wrong / signing-skew / callback-host, plus the
    app-level operators (cookie-attr, migration-skip, dep-down) that need a harness and are
    recorded as NOT applied rather than quietly counted;
  * the admission shape: baseline probe must PASS, then each fault must make it FAIL.

FIX-ENVFAULT-UNDETECTED-IS-A-GAP (the v3.8 defect): v3.8 let an environment fault the suite
failed to notice read as "an environment problem" rather than as a detection gap. Here an
applied operator that the probe does not catch is `detected: false`, and `envfault_detected`
fails on it. A probe run that HANGS or crashes is likewise `detected: false` — an unknown is
never an assertion.

FIX-ENVFAULT-MISSING-IS-EMPTY: v3.8 `unset` the variable in a `subprocess.Popen` environment
it built from `os.environ`. The v4.0 adapter builds the child environment by ALLOWLIST, so an
application variable is not inherited at all and "unset" would be a no-op that silently
applied nothing. `env-missing` is therefore applied as an EMPTY value — the observable form of
"the deploy env forgot to set it" — and the mutation string says so.
"""
import re
from pathlib import Path

from ..models.evidence import EvidenceKind
from .base import Collector

RC_TIMEOUT = 124
RC_OUTPUT_LIMIT = 125
RC_SPAWN_FAILED = 127
ERROR_RCS = (RC_TIMEOUT, RC_OUTPUT_LIMIT, RC_SPAWN_FAILED)

#: v3.8 verbatim. Keys whose corruption plausibly breaks auth/session.
_SECRETY = re.compile(r"(secret|token|jwt|session|sign|key|password|passwd|oauth|client_secret)", re.I)
_HOSTY = re.compile(r"(callback|redirect|origin|host|url|issuer|audience)", re.I)

_ENV_REF = re.compile(
    r"""process\.env\.([A-Z0-9_]+)|process\.env\[\s*['"]([A-Z0-9_]+)['"]\s*\]"""
    r"""|os\.environ(?:\.get)?\(\s*['"]([A-Z0-9_]+)['"]"""
    r"""|os\.environ\[\s*['"]([A-Z0-9_]+)['"]\s*\]"""
    r"""|os\.getenv\(\s*['"]([A-Z0-9_]+)['"]""")

SKIP = {"node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__",
        "shipgate-workdir", "coverage"}
SRC_EXT = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".py")


def env_keys(root):
    """v3.8 `_env_keys`: declared keys from .env.example plus keys the source actually reads."""
    root = Path(root)
    keys = set()
    ex = root / ".env.example"
    if ex.exists():
        try:
            for line in ex.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    keys.add(line.split("=", 1)[0].strip())
        except OSError:
            pass
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in SRC_EXT:
            continue
        if set(f.parts) & SKIP:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for m in _ENV_REF.finditer(text):
            got = next((g for g in m.groups() if g), None)
            if got:
                keys.add(got)
    return sorted(keys)


def plan_operators(root):
    """v3.8 `_plan_ops`, unchanged in ordering and note text."""
    keys = env_keys(root)
    ops = []
    for k in keys:
        # _HOSTY before _SECRETY: OAUTH_CALLBACK_URL matches both, and its login-breaking
        # fault is a WRONG HOST, not a rotated secret. Classify by the more specific signal.
        if _HOSTY.search(k):
            ops.append({"op": "callback-host", "key": k, "value": "https://wrong.example.invalid",
                        "note": f"point {k} at the wrong host — the OAuth/redirect callback then "
                                f"mismatches and the IdP refuses the round-trip"})
        elif _SECRETY.search(k):
            ops.append({"op": "signing-skew", "key": k, "value": "shipgate-rotated-nonce",
                        "note": f"rotate {k} so tokens signed with the old value are rejected — a "
                                f"session/JWT secret mismatched across services breaks login while "
                                f"every source test still passes"})
            ops.append({"op": "env-wrong", "key": k, "value": "shipgate-wrong-value",
                        "note": f"set {k} to a plausible-wrong value"})
        else:
            ops.append({"op": "env-missing", "key": k, "value": "",
                        "note": f"blank {k} — a required var the deploy env forgot to set"})
    ops += [
        {"op": "cookie-attr", "attr": "Secure",
         "note": "force session cookie Secure=true over plain-HTTP test transport, so the browser "
                 "silently drops it and the user cannot stay logged in"},
        {"op": "migration-skip",
         "note": "boot against a schema missing the latest migration — the login query 500s on a "
                 "column that does not exist yet"},
        {"op": "dep-down", "name": "auth-idp",
         "note": "make the auth dependency unreachable — the CUJ must fail loudly, not silently "
                 "fall through to an anonymous session"},
    ]
    return ops


APPLICABLE = ("env-missing", "env-wrong", "signing-skew", "callback-host")


def _mutation_text(op):
    kind = op["op"]
    if kind == "env-missing":
        return "set to the empty string (the observable form of 'not set')"
    if kind == "signing-skew":
        return f"rotated to {op.get('value')!r}"
    if kind == "callback-host":
        return f"pointed at {op.get('value')!r}"
    if kind == "env-wrong":
        return f"set to {op.get('value')!r}"
    return op.get("note", kind)


class EnvFaultCollector(Collector):
    """Apply environment/config faults and record whether the CUJ probe notices them.

    Options: `cuj_probe` (the command whose exit code is the journey verdict), `test_cmd`
    fallback, `env_fault_max` (default 6), `env_fault_timeout` (default 300).
    """

    kind = EvidenceKind.ENV_FAULT
    name = "env-fault"
    version = "4.2.2"

    def collect(self, ctx):
        root = Path(ctx.run_area or ctx.repo).resolve()
        if not root.is_dir():
            return self.error(ctx, f"run area is not a directory: {root}")
        probe = (ctx.option("cuj_probe") or "").strip()
        source = "cuj_probe"
        if not probe:
            commands = ctx.stack.get("commands") if isinstance(ctx.stack, dict) else None
            probe = (ctx.option("test_cmd")
                     or (commands.get("test") if isinstance(commands, dict) else None) or "").strip()
            source = "test command (no cuj_probe was declared)"
        timeout = int(ctx.option("env_fault_timeout", 300) or 300)
        limit = int(ctx.option("env_fault_max", 6) or 6)

        planned = plan_operators(root)
        if not probe:
            operators = [self._not_applied(op, "no CUJ probe or test command is available, so no "
                                                "environment fault could be applied")
                         for op in planned]
            return self.collected(ctx, {
                "operators": operators, "baselineHealthy": False, "cujProbe": "",
            }, note="no probe command; the environment fault loop was not run",
               uncovered=["env-fault: no probe command to detect a fault with"])

        # --- baseline: the probe must pass with no fault applied ------------------------------
        base = self._run(ctx, root, probe, {}, timeout)
        base_ok = bool(base is not None and hasattr(base, "returncode")
                       and base.returncode == 0 and not base.timed_out)
        if not base_ok:
            why = self._why(base)
            operators = [self._not_applied(op, f"baseline probe did not pass ({why}); a fault "
                                                f"cannot be distinguished from a broken probe")
                         for op in planned]
            return self.collected(ctx, {
                "operators": operators, "baselineHealthy": False, "cujProbe": probe,
            }, note=f"baseline probe failed ({why}); no environment fault was applied",
               uncovered=["env-fault: the baseline probe is not healthy"])

        operators, applied_n = [], 0
        for op in planned:
            if op["op"] not in APPLICABLE:
                operators.append(self._not_applied(
                    op, "needs an app/schema-level harness (the operator changes the deployed "
                        "system, not an environment variable)"))
                continue
            if applied_n >= limit:
                operators.append(self._not_applied(
                    op, f"not applied: the per-run operator cap ({limit}) was reached"))
                continue
            key = op.get("key")
            res = self._run(ctx, root, probe, {key: str(op.get("value", ""))}, timeout)
            applied_n += 1
            if res is None or not hasattr(res, "returncode"):
                # FIX-ENVFAULT-UNDETECTED-IS-A-GAP: an unknown is not a detection.
                detected, detail = False, f"the probe could not be run under the fault ({res})"
            elif res.timed_out or res.returncode in ERROR_RCS:
                detected, detail = False, (f"the probe HUNG or could not complete under the fault "
                                           f"(rc={res.returncode}); detection is unknown, which is "
                                           f"a gap, not a pass")
            elif res.returncode != 0:
                detected, detail = True, f"the probe failed under the fault (rc={res.returncode})"
            else:
                detected, detail = False, ("the probe PASSED with the fault applied — a broken "
                                           "environment went unnoticed; strengthen the probe to "
                                           "assert a logged-in state, not just a 200")
            operators.append({
                "id": f"{op['op']}:{key}",
                "variable": str(key),
                "mutation": _mutation_text(op),
                "applied": True,
                "detected": bool(detected),
                "detail": detail,
            })

        payload = {
            "operators": operators,
            "baselineHealthy": True,
            "cujProbe": probe,
            "probeSource": source,
            "declaredKeys": env_keys(root),
        }
        undetected = [o for o in operators if o["applied"] and not o["detected"]]
        note = (f"{applied_n} environment fault(s) applied against `{probe}`; "
                f"{len(undetected)} undetected")
        return self.collected(ctx, payload, note=note)

    # --- internals ----------------------------------------------------------------------
    def _not_applied(self, op, detail):
        return {
            "id": f"{op['op']}:{op.get('key') or op.get('attr') or op.get('name') or '-'}",
            "variable": str(op.get("key") or ""),
            "mutation": _mutation_text(op),
            "applied": False,
            "detected": False,
            "detail": detail,
        }

    def _run(self, ctx, root, command, overrides, timeout):
        try:
            return ctx.adapter.run_target(command=command, cwd=str(root), timeout=timeout,
                                          env_extra=overrides or None,
                                          label=f"env-fault probe: {command}")
        except Exception as exc:  # noqa: BLE001
            return exc

    def _why(self, res):
        if res is None or not hasattr(res, "returncode"):
            return f"the probe could not be started ({res})"
        if res.timed_out:
            return "the probe hung and was killed"
        return f"rc={res.returncode}"
