"""Environment sanitisation for target-controlled processes.

Target code runs as the same OS user and can read its own environment. The gate may hold
signing keys, a verifier token, OIDC material. So the adapter builds the child environment
by ALLOWLIST, not by denylist.

v3.8 used a denylist (`COSIGN_*`, `GITHUB_TOKEN`, …). A denylist is wrong by default: any
secret the operator adds tomorrow — `NPM_TOKEN`, `AWS_SESSION_TOKEN`, `SLACK_WEBHOOK` —
is inherited until someone remembers to add it. Here the child gets a fixed base set plus
whatever the caller explicitly passes, and everything else is dropped.
"""
import os

#: Variables every child legitimately needs. Nothing secret belongs in this list.
BASE_ALLOW = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "SHELL", "USER", "LOGNAME",
    "TMPDIR", "PWD",
)

#: Ecosystem variables that are safe and usually necessary for a build/test to work.
TOOLCHAIN_ALLOW = (
    "NODE_ENV", "NODE_OPTIONS", "NODE_PATH", "npm_config_cache", "npm_config_prefix",
    "PYTHONPATH", "PYTHONHASHSEED", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
    "VIRTUAL_ENV", "PIP_CACHE_DIR", "PLAYWRIGHT_BROWSERS_PATH",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "JAVA_HOME", "GRADLE_USER_HOME", "MAVEN_OPTS",
    "DOTNET_CLI_TELEMETRY_OPTOUT", "CARGO_HOME", "RUSTUP_HOME", "GOPATH", "GOCACHE",
    "CI",
)

#: Non-secret run context collectors legitimately read.
RUN_CONTEXT_ALLOW = (
    "SHIPGATE_RUN_ID", "SHIPGATE_ROUND", "SHIPGATE_ROLE", "SHIPGATE_RUN_AREA",
)

#: Names never forwarded even if a caller asks for them. The last line of defence against
#: a collector that passes through its own environment by mistake.
NEVER_FORWARD_PREFIXES = (
    "COSIGN_", "SIGSTORE_", "FULCIO_", "REKOR_", "AGE_", "AWS_", "AZURE_", "GCP_",
    "GOOGLE_APPLICATION", "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "SHIPGATE_SIGNING",
    "SHIPGATE_VERIFIER", "SHIPGATE_ATTEST", "SHIPGATE_SECRET", "SHIPGATE_AUTHORITY",
    "ACTIONS_ID_TOKEN", "ACTIONS_RUNTIME_TOKEN",
)
NEVER_FORWARD_EXACT = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "PYPI_TOKEN", "DOCKER_PASSWORD",
    "SSH_AUTH_SOCK", "GPG_AGENT_INFO",
})


def is_forbidden(name):
    upper = name.upper()
    if upper in NEVER_FORWARD_EXACT:
        return True
    return any(upper.startswith(p) for p in NEVER_FORWARD_PREFIXES)


def build_env(extra=None, allow_extra_names=(), source=None):
    """Construct the child environment.

    `extra` are explicit name->value pairs the caller wants set (e.g. a seeded
    `DATABASE_URL`). `allow_extra_names` passes through named variables from the parent.
    Both are still refused if the name is forbidden — an explicit request cannot leak a
    signing key.
    """
    src = os.environ if source is None else source
    allowed = set(BASE_ALLOW) | set(TOOLCHAIN_ALLOW) | set(RUN_CONTEXT_ALLOW)
    allowed |= {n for n in allow_extra_names if not is_forbidden(n)}

    env = {}
    for name in sorted(allowed):
        if name in src and not is_forbidden(name):
            env[name] = src[name]

    for name, value in sorted((extra or {}).items()):
        if is_forbidden(name):
            continue
        env[name] = str(value)

    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    # Deterministic, non-interactive, no telemetry phone-home from the child.
    env.setdefault("CI", "1")
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return env


def leaked_names(env, source=None):
    """Diagnostic: which forbidden names would have been inherited but were dropped."""
    src = os.environ if source is None else source
    return sorted(n for n in src if is_forbidden(n) and n not in env)
