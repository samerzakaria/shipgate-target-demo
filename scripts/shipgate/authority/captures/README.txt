The capture corpus lives in captures.json, one file instead of 56.

WHY. A Claude Skill package may contain at most 200 files, and it may not contain a nested
zip. Two parallel trees of 28 captures each — raw/ byte-exact as the tools wrote it,
normalized/ the UTF-8 copy — spent more than a quarter of that budget on fixtures nothing
outside this kit ever opens, and the obvious container (a zip) is not allowed. So it is
JSON with base64 payloads.

That is worse compression and better inspection. The file opens in any editor. Every entry
carries its own sha256 and byte count beside its payload, and you can read one out with
nothing but the standard library:

    python3 -c "import base64,json,sys; \
      print(base64.b64decode(json.load(open('captures.json'))['entries']['normalized/repo.json']['b64']).decode())"

NOTHING ELSE CHANGED. base64 is lossless, so every capture is the byte string the tool
produced: the BOMs, the CRLFs and the UTF-16LE payloads are intact, and every sha256 pinned
in schemas/SHAPES.json still re-hashes and still matches. The rule that a shape may be
VALIDATED only from normalized/ is now enforced by the container's own key namespace rather
than by a directory path, and read() re-verifies each payload against the digest recorded
beside it on every decode.

THE COMMANDS (run from <skill>/scripts):

    python3 -m shipgate.authority.capturestore --extract /tmp/captures
    python3 -m shipgate.authority.capturestore --list
    python3 -m shipgate.authority.capturestore --verify

--verify re-hashes every entry against SHA256SUMS.txt, which was written by the capture
author at capture time and travels inside the container.

TO REBUILD IT (deterministic — sorted keys, fixed separators, ASCII only, no timestamps):

    python3 -m shipgate.authority.capturestore --pack /tmp/captures

PROVENANCE-ADDENDUM.txt is an entry in the container, alongside the two trees.
