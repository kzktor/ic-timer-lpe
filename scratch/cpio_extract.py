#!/usr/bin/env python3
"""Extract a gzipped newc cpio archive.  Usage: cpio_extract.py ARCHIVE OUTDIR [name ...]"""
import gzip
import os
import sys


def main():
    arc, outdir = sys.argv[1], sys.argv[2]
    want = set(sys.argv[3:])
    os.makedirs(outdir, exist_ok=True)
    with gzip.open(arc, "rb") as f:
        data = f.read()
    off = 0
    while True:
        if data[off:off + 6] not in (b"070701", b"070702"):
            raise SystemExit("bad magic at %#x" % off)
        hdr = data[off:off + 110]
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        body = off + 110 + namesize
        body = (body + 3) & ~3
        if name == "TRAILER!!!":
            break
        if not want or name in want:
            path = os.path.join(outdir, name.lstrip("/"))
            os.makedirs(os.path.dirname(path) or outdir, exist_ok=True)
            with open(path, "wb") as g:
                g.write(data[body:body + filesize])
            print("%-32s %8d" % (name, filesize))
        off = body + filesize
        off = (off + 3) & ~3


main()
