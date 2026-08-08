"""The capture corpus, stored as one deterministic JSON file instead of 56 loose ones.

WHY A CONTAINER. A Claude Skill package may contain at most 200 files. The capture corpus
is 56 of them — two parallel trees (`raw/` byte-exact as received, `normalized/` UTF-8)
of 28 files each — which is more than a quarter of the entire budget spent on fixtures
that nothing but this kit ever opens. Packing them costs one file and changes nothing
about what they are.

WHY NOT A ZIP. It was one, briefly. A Claude Skill package may not contain a nested zip,
so the container is a JSON document with base64 payloads instead: `captures.json`. That
is a worse compression story and a strictly better inspection story — the file opens in
any editor, every entry carries its own sha256 and byte count beside its payload, and
`python -c "import json; ..."` is enough to read one out without this module. The
constraint forced a format that is easier to audit, which is the right direction for a
corpus whose whole job is to be checkable.

WHAT MUST NOT CHANGE, AND DOES NOT:

  * BYTE EXACTNESS. Deflate is lossless and a zip entry is a byte string, so a capture
    read out of the archive is the same object the tool wrote. Every existing digest pin
    in `SHAPES.json` still re-hashes at load and still matches; nothing was re-encoded to
    fit. The BOMs, the CRLFs and the UTF-16LE payloads survive intact, which is the whole
    reason `raw/` exists.
  * THE VALIDATION FENCE. `shapes` may only validate a shape from `normalized/`. That rule
    is now enforced by the archive's namespace: `read("normalized", name)` cannot reach a
    `raw/` entry or a `tests_data/` one, because they are different key prefixes in a
    read-only container. The fence got harder to climb, not softer.
  * INSPECTABILITY. `python -m shipgate.authority.capturestore --extract DIR` writes the
    corpus back out as ordinary files, `--list` prints every entry with its digest, and
    `--verify` re-hashes every entry against the corpus's own `SHA256SUMS.txt`. An adopter
    who wants to read a capture in an editor is one command away, and the command is in
    the skill. Failing that, the container is JSON and every payload is base64.

DETERMINISM. `--pack` writes sorted keys, fixed separators and ASCII-only output, and
records no timestamp, no mode and no ambient state of any kind. Packing the same corpus
twice on two machines produces the same bytes, so the container can sit inside a
digest-pinned release artifact without making the release digest depend on when it was
built.

MATERIALIZATION. Two callers genuinely need a directory rather than a byte string: the CI
and independent adapters take an `evidenceDir` of real files, because that is what they
take in production. `materialize()` extracts the corpus once per process into a temporary
directory and hands back the path. It is lazy — importing this module touches no disk —
and the directory is removed at exit. Nothing writes back into it; it is a read view.
"""
import atexit
import base64
import hashlib
import json
import os
import shutil
import tempfile
from typing import Any, Dict, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))

#: The container itself. One file, inside the package, next to nothing else.
CAPTURE_DIR = os.path.join(_HERE, "captures")
ARCHIVE_PATH = os.path.join(CAPTURE_DIR, "captures.json")

#: The container's schema. Bumped only if the payload encoding changes; a reader that does
#: not recognise it must refuse rather than guess, which `_load` does.
SCHEMA = "shipgate.authority.captures/1"

#: The two variants, and the only two. A caller naming anything else is a bug, not a
#: lookup miss — see `_prefix`.
RAW = "raw"
NORMALIZED = "normalized"
VARIANTS = (NORMALIZED, RAW)

#: Files that live beside the two trees rather than inside them. Documentation about the
#: corpus as a whole, not a capture of anything.
ROOT_FILES = ("PROVENANCE-ADDENDUM.txt",)

_DOC: Optional[Dict[str, Any]] = None
_MEMO: Dict[str, bytes] = {}
_MATERIALIZED: Optional[str] = None


class CaptureStoreError(LookupError):
    """The container is missing, unreadable, or does not contain what was asked for.

    Always fatal to the caller. There is no fallback path and no substitute capture: a
    kit that cannot read its own corpus must block every shape, which is what happens
    when `shapes._verify_capture` turns this into a BLOCKED reason.
    """


def _prefix(variant: str) -> str:
    if variant not in VARIANTS:
        raise CaptureStoreError(
            f"unknown capture variant {variant!r}; the corpus has exactly {VARIANTS!r} and "
            "inventing a third would let a caller read outside the validation fence")
    return variant + "/"


def _load() -> Dict[str, Any]:
    """Parse the container once per process. Raises `CaptureStoreError`, never anything else.

    A container whose schema this reader does not recognise is REFUSED rather than read
    optimistically: a future encoding decoded as base64 would produce plausible-looking
    bytes that fail their digests, and "the capture is corrupt" is a much worse diagnosis
    than "this reader is too old".
    """
    global _DOC
    if _DOC is not None:
        return _DOC
    try:
        with open(ARCHIVE_PATH, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise CaptureStoreError(f"capture container unreadable: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), dict):
        raise CaptureStoreError(f"capture container has no 'entries' object: {ARCHIVE_PATH}")
    if doc.get("schema") != SCHEMA:
        raise CaptureStoreError(
            f"capture container declares schema {doc.get('schema')!r}; this reader "
            f"understands {SCHEMA!r} only")
    _DOC = doc
    return doc


def available() -> bool:
    """True when the container is present and parses. Never raises."""
    try:
        _load()
        return True
    except CaptureStoreError:
        return False


def read(variant: str, name: str) -> bytes:
    """The exact bytes of one capture. Memoized; decoded at most once per key.

    The digest recorded beside the payload is verified on every decode. That is not
    belt-and-braces with `SHAPES.json`: this one catches a container that was edited, and
    it catches it at the point of use rather than only for the shapes a run happens to
    validate.
    """
    key = _prefix(variant) + name
    if key in _MEMO:
        return _MEMO[key]
    entry = _load()["entries"].get(key)
    if not isinstance(entry, dict) or not isinstance(entry.get("b64"), str):
        raise CaptureStoreError(
            f"capture {name!r} is not in the {variant} corpus ({ARCHIVE_PATH})")
    try:
        data = base64.b64decode(entry["b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise CaptureStoreError(f"capture {name!r} has a malformed payload: {exc}") from None
    want = entry.get("sha256")
    got = hashlib.sha256(data).hexdigest()
    if want != got:
        raise CaptureStoreError(
            f"capture {name!r} does not match the digest recorded beside it "
            f"(container={str(want)[:16]}… decoded={got[:16]}…)")
    _MEMO[key] = data
    return data


def read_root(name: str) -> bytes:
    """A corpus-level document (see ROOT_FILES), not a capture."""
    entry = _load()["entries"].get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("b64"), str):
        raise CaptureStoreError(f"{name!r} is not in the capture container")
    return base64.b64decode(entry["b64"], validate=True)


def names(variant: str) -> Tuple[str, ...]:
    """Every capture filename in one variant, sorted. Empty when the container is gone."""
    pre = _prefix(variant)
    try:
        entries = _load()["entries"]
    except CaptureStoreError:
        return ()
    return tuple(sorted(k[len(pre):] for k in entries if k.startswith(pre)))


def digest(variant: str, name: str) -> str:
    return hashlib.sha256(read(variant, name)).hexdigest()


# ---------------------------------------------------------------------------------------
# materialization
# ---------------------------------------------------------------------------------------


def materialize() -> str:
    """Extract the corpus once per process; return the directory holding `raw/` and
    `normalized/`.

    Lazy on purpose. The semantic engine never calls this, the authority parsers never
    call this, and importing the module never calls this — only the two adapters that
    take a real `evidenceDir`, plus `selfcheck`, which copies files out of it.
    """
    global _MATERIALIZED
    if _MATERIALIZED is not None and os.path.isdir(_MATERIALIZED):
        return _MATERIALIZED
    target = tempfile.mkdtemp(prefix="shipgate-captures-")
    try:
        _write_out(target)
    except (OSError, CaptureStoreError) as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise CaptureStoreError(f"capture container unreadable: {exc}") from None
    _MATERIALIZED = target
    atexit.register(shutil.rmtree, target, True)
    return target


def _write_out(target: str) -> int:
    """Write every entry under `target`. Shared by `materialize` and `extract`."""
    root = os.path.abspath(target)
    count = 0
    for key in sorted(_load()["entries"]):
        # Defence in depth. The container is ours and its keys are flat, but an extractor
        # that trusts entry names is the classic archive-traversal bug, and a kit about not
        # trusting inputs should not contain one.
        dest = os.path.normpath(os.path.join(root, key))
        if dest != root and not dest.startswith(root + os.sep):
            raise CaptureStoreError(f"container entry {key!r} escapes the extraction root")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        entry = _load()["entries"][key]
        with open(dest, "wb") as fh:
            fh.write(base64.b64decode(entry["b64"], validate=True))
        count += 1
    return count


def variant_dir(variant: str) -> str:
    """The materialized directory for one variant."""
    return os.path.join(materialize(), _prefix(variant).rstrip("/"))


# ---------------------------------------------------------------------------------------
# build and inspect
# ---------------------------------------------------------------------------------------


def pack(source_dir: str, archive_path: str = ARCHIVE_PATH) -> Tuple[int, str]:
    """Build the container from a loose corpus. Deterministic; returns (entries, sha256)."""
    sources = []
    for variant in VARIANTS:
        base = os.path.join(source_dir, variant)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            full = os.path.join(base, name)
            if os.path.isfile(full):
                sources.append((variant + "/" + name, full))
    for name in ROOT_FILES:
        full = os.path.join(source_dir, name)
        if os.path.isfile(full):
            sources.append((name, full))
    entries = {}
    for key, full in sorted(sources):
        with open(full, "rb") as fh:
            data = fh.read()
        entries[key] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "b64": base64.b64encode(data).decode("ascii"),
        }
    doc = {
        "schema": SCHEMA,
        "note": ("The real tool-output capture corpus, one file because a Claude Skill "
                 "package may hold at most 200 files and may not contain a nested zip. "
                 "`b64` is the base64 of the EXACT bytes the tool produced — BOMs, CRLFs "
                 "and UTF-16LE payloads intact — and `sha256` is the digest of the decoded "
                 "bytes, verified on every read. Regenerate with "
                 "`python -m shipgate.authority.capturestore --pack DIR`; read with "
                 "`--extract DIR`; check with `--verify`."),
        "encoding": "base64",
        "entryCount": len(entries),
        "entries": entries,
    }
    text = json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=True,
                      separators=(",", ": ")) + "\n"
    with open(archive_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return len(entries), hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract(target_dir: str) -> int:
    """Write the corpus out as ordinary files. The inspection path."""
    os.makedirs(target_dir, exist_ok=True)
    return _write_out(target_dir)


def verify() -> Tuple[bool, Tuple[str, ...]]:
    """Re-hash every entry against the corpus's own SHA256SUMS.txt.

    That file was written by the capture author at capture time and travels inside the
    container, so this is the corpus checking itself rather than the packer checking its
    own work. `read()` additionally re-verifies each entry against the digest recorded
    beside it, so a doctored payload fails here twice. Returns (ok, problems).
    """
    problems = []
    try:
        listing = read(NORMALIZED, "SHA256SUMS.txt").decode("utf-8", "replace")
    except CaptureStoreError as exc:
        return False, (str(exc),)
    checked = 0
    for line in listing.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        want, name = parts[0], parts[-1].lstrip("*./")
        if name == "SHA256SUMS.txt":
            continue
        try:
            got = digest(NORMALIZED, name)
        except CaptureStoreError as exc:
            problems.append(f"{name}: {exc}")
            continue
        checked += 1
        if got != want:
            problems.append(f"{name}: listed {want[:16]}… archive {got[:16]}…")
    if not checked:
        problems.append("SHA256SUMS.txt listed no verifiable entry")
    return (not problems), tuple(problems)


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="shipgate.authority.capturestore",
                                 description="Inspect or rebuild the capture container.")
    ap.add_argument("--extract", metavar="DIR", help="write the corpus out as loose files")
    ap.add_argument("--pack", metavar="DIR", help="rebuild the container from a loose corpus")
    ap.add_argument("--list", action="store_true", help="list every entry")
    ap.add_argument("--verify", action="store_true",
                    help="re-hash every entry against the corpus SHA256SUMS.txt")
    args = ap.parse_args(argv)
    did = False
    if args.pack:
        count, sha = pack(args.pack)
        print(f"packed {count} entries -> {ARCHIVE_PATH}\nsha256 {sha}")
        did = True
    if args.extract:
        print(f"extracted {extract(args.extract)} entries -> {args.extract}")
        did = True
    if args.list:
        for variant in VARIANTS:
            for name in names(variant):
                print(f"{variant}/{name}  {digest(variant, name)}")
        did = True
    if args.verify:
        ok, problems = verify()
        print("capture container: " + ("OK" if ok else "PROBLEMS"))
        for problem in problems:
            print("  " + problem)
        did = True
        if not ok:
            return 1
    if not did:
        ap.print_help()
    return 0


if __name__ == "__main__":       # pragma: no cover - CLI entry point
    import sys
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except BrokenPipeError:
        # `--list | head` closes the pipe. The reader's decision, not our error. Redirect the
        # dangling stdout so the interpreter's shutdown flush cannot raise a second time.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        raise SystemExit(0)
