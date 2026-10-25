#!/usr/bin/env python3
"""Rebuild a gzipped newc cpio, replacing named entries.

Usage: cpio_repack.py SRC.cpio.gz DST.cpio.gz name=path [name=path ...]
Existing entries keep their header; replaced ones get the new size (their
mode/uid/gid are kept).  Any trailing non-cpio bytes in SRC are dropped.
"""
import gzip
import sys


def main():
    src, dst = sys.argv[1], sys.argv[2]
    repl = {}
    for spec in sys.argv[3:]:
        name, path = spec.split("=", 1)
        with open(path, "rb") as f:
            repl[name.lstrip("/")] = f.read()
    with gzip.open(src, "rb") as f:
        data = f.read()
    out = bytearray()
    off = 0
    seen = set()
    while True:
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            raise SystemExit("bad magic at %#x" % off)
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        body_off = (off + 110 + namesize + 3) & ~3
        if name == "TRAILER!!!":
            out += data[off:body_off]
            out += b"\0" * ((4 - len(out) % 4) % 4)
            break
        body = data[body_off:body_off + filesize]
        if name in repl:
            body = repl[name]
            hdr = hdr[:54] + ("%08X" % len(body)).encode() + hdr[62:]
            seen.add(name)
        out += hdr + data[off + 110:off + 110 + namesize]
        out += b"\0" * ((4 - len(out) % 4) % 4)
        out += body
        out += b"\0" * ((4 - len(out) % 4) % 4)
        off = (body_off + filesize + 3) & ~3
    missing = set(repl) - seen
    if missing:
        raise SystemExit("entries not found: %s" % ", ".join(sorted(missing)))
    with open(dst, "wb") as f:
        f.write(gzip.compress(bytes(out), 9))


main()
