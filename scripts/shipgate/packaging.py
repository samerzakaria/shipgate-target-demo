"""What may and may not go into a release artifact.

THIS LIVES IN THE SKILL ON PURPOSE. It used to live in the author's private build script,
which is why the v4.0 artifact shipped five `.pytest_cache` files — including
`v/cache/lastfailed`, a record of which of the author's tests had failed during development.
External audit found them; nothing in the release did. A packaging rule that only exists in
a build script is a rule the shipped product cannot check, cannot document and cannot hand
to an adopter who repackages it.

So the rule is a module: `build.py` imports it, `tests/boundary/test_skill_metadata.py`
asserts against it, and anyone re-zipping this skill has the same list.

Two loader constraints are encoded here as well, both learned the expensive way — each was
discovered by an upload being rejected rather than by anything in the release procedure:

  * `MAX_FILES` — a skill package may contain at most 200 files. The first v4.0 artifact
    held 213.
  * `ARCHIVE_MAGIC` — a skill package may not contain a NESTED ARCHIVE. The fix for the
    file count was a zip of the capture corpus, which the loader refused in turn. The magic
    list is deliberately wider than "zip": "it is not technically a zip" is the reasoning
    that would produce a third rejected upload.
"""
import os

#: Directories that are never part of a release, whatever created them.
EXCLUDE_DIRS = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
    ".hypothesis", "htmlcov", ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", ".venv", "venv", ".eggs", ".ipynb_checkpoints",
})

#: File suffixes that are never part of a release.
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".pyd", ".orig", ".rej", ".swp", ".log")

#: Exact filenames that are never part of a release.
EXCLUDE_NAMES = frozenset({".DS_Store", "Thumbs.db", ".coverage", "coverage.xml"})

#: Directories that the ACT OF TESTING creates, so a check running inside the tree cannot
#: assert their absence. They are still excluded at package time — this set exists so the
#: distinction between "cannot be asserted here" and "is allowed" stays written down rather
#: than implied by a quietly loosened test.
CREATED_BY_TESTING = frozenset({"__pycache__", ".pytest_cache"})

#: The loader's ceiling, and the headroom the suite insists on so the failure mode is
#: "you are close" rather than "the upload was refused".
MAX_FILES = 200
HEADROOM = 20

#: Container formats a packager might reach for. None may appear inside a skill package.
ARCHIVE_MAGIC = (
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "empty zip"), (b"PK\x07\x08", "spanned zip"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"!<arch>\n", "ar"), (b"\x28\xb5\x2f\xfd", "zstd"),
)


def excluded_part(relative_path):
    """The first path component that disqualifies this path, or ''. Accepts str or Path."""
    parts = str(relative_path).replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part in EXCLUDE_DIRS:
            return part
    leaf = parts[-1] if parts else ""
    if leaf in EXCLUDE_DIRS:
        return leaf
    if leaf in EXCLUDE_NAMES:
        return leaf
    if leaf.endswith(EXCLUDE_SUFFIXES):
        return leaf
    return ""


def should_exclude(relative_path):
    return bool(excluded_part(relative_path))


def archive_kind(head_bytes):
    """The container format these leading bytes announce, or ''."""
    for magic, kind in ARCHIVE_MAGIC:
        if head_bytes.startswith(magic):
            return kind
    return ""


def shippable_files(root):
    """Every path under `root` that belongs in a release artifact, sorted."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if not should_exclude(os.path.relpath(full, root)):
                out.append(full)
    return sorted(out)
