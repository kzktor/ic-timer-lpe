#!/usr/bin/env python3
"""Pack files into a gzipped newc cpio initramfs."""
import gzip
import os
import sys


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
    out_path = sys.argv[1]
    files = sys.argv[2:]
    blob = b""
    ino = 1
    for spec in files:
        src, name = spec.split(":", 1)
        with open(src, "rb") as f:
            data = f.read()
        mode = 0o100755 if os.access(src, os.X_OK) else 0o100644
        blob += entry(name, data, mode, ino)
        ino += 1
    blob += entry("TRAILER!!!", b"", 0, 0)
    with gzip.open(out_path, "wb", 9) as g:
        g.write(blob)
    print("wrote %s (%d bytes raw, %d files)" % (out_path, len(blob),
                                                  len(files)))


if __name__ == "__main__":
    main()
