#!/usr/bin/env python3
"""Repack initramfs: keep every entry, replace 'exploit' with the new build."""
import gzip
import sys


def parse(blob):
    i = 0
    out = []
    while True:
        assert blob[i:i + 6] == b"070701", (i, blob[i:i + 6])
        f = [int(blob[i + 6 + 8 * j:i + 14 + 8 * j], 16) for j in range(13)]
        namesz, size, mode = f[11], f[6], f[1]
        name = blob[i + 110:i + 110 + namesz - 1].decode()
        i += 110 + namesz
        i = (i + 3) & ~3
        data = blob[i:i + size]
        i += size
        i = (i + 3) & ~3
        if name == "TRAILER!!!":
            break
        out.append([name, mode, data])
    return out


def entry(name, data, mode, ino):
    namez = name.encode() + b"\0"
    hdr = b"070701" + b"".join(b"%08X" % f for f in (
        ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(namez), 0))
    out = hdr + namez
    out += b"\0" * ((4 - len(out) % 4) % 4)
    out += data
    out += b"\0" * ((4 - len(data) % 4) % 4)
    return out


def main():
    src, dst, repl_name, repl_src = sys.argv[1:5]
    blob = gzip.open(src, "rb").read()
    entries = parse(blob)
    data = open(repl_src, "rb").read()
    hit = 0
    out = b""
    ino = 1
    for name, mode, d in entries:
        if name == repl_name:
            d = data
            hit += 1
        out += entry(name, d, mode, ino)
        ino += 1
    assert hit == 1, hit
    out += entry("TRAILER!!!", b"", 0, 0)
    with gzip.open(dst, "wb", 9) as g:
        g.write(out)
    print("wrote %s (%d entries, replaced %s)" % (dst, ino - 1, repl_name))


if __name__ == "__main__":
    main()
