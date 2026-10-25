#!/usr/bin/env python3
"""List or extract a newc cpio archive (gzip or raw). Stdlib only.

usage: cpiocat.py ARCHIVE [list|extract OUTDIR] [NAME...]
"""
import gzip
import io
import os
import sys


def read_archive(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    out = []
    pos = 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] != b"070701":
            raise SystemExit("bad magic at %d" % pos)
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16)
                  for i in range(13)]
        mode, size, namesz = fields[1], fields[6], fields[11]
        name_start = pos + 110
        name = data[name_start:name_start + namesz].rstrip(b"\0").decode(
            "utf-8", "replace")
        body_start = (name_start + namesz + 3) & ~3
        body = data[body_start:body_start + size]
        pos = (body_start + size + 3) & ~3
        if name == "TRAILER!!!":
            break
        out.append((name, mode, body))
    return out


def main():
    archive = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "list"
    entries = read_archive(archive)
    if cmd == "list":
        for name, mode, body in entries:
            kind = "d" if mode & 0o170000 == 0o040000 else "-"
            print("%s %04o %7d %s" % (kind, mode & 0o7777, len(body), name))
        return
    if cmd == "extract":
        dest = sys.argv[3]
        for name, mode, body in entries:
            path = os.path.join(dest, name.lstrip("/"))
            if mode & 0o170000 == 0o040000:
                os.makedirs(path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "wb") as f:
                f.write(body)
            os.chmod(path, mode & 0o7777)
        print("extracted %d entries to %s" % (len(entries), dest))
        return
    if cmd == "cat":
        want = sys.argv[3]
        for name, mode, body in entries:
            if name.lstrip("/") == want.lstrip("/"):
                sys.stdout.buffer.write(body)
                return
        raise SystemExit("not found: %s" % want)
    raise SystemExit("unknown command %s" % cmd)


if __name__ == "__main__":
    main()
