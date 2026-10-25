#!/usr/bin/env python3
"""Decode an Android boot-image LZ4 legacy-frame kernel (magic 0x184C2102)."""
import struct
import sys


def lz4_block(src, out):
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                s = src[i]
                i += 1
                ll += s
                if s != 255:
                    break
        if i + ll > n:
            raise ValueError("literal overrun")
        out += src[i:i + ll]
        i += ll
        if i >= n:
            break
        if i + 2 > n:
            raise ValueError("no offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0:
            raise ValueError("zero offset")
        ml = (token & 15) + 4
        if (token & 15) == 15:
            while True:
                s = src[i]
                i += 1
                ml += s
                if s != 255:
                    break
        start = len(out) - off
        if start < 0:
            raise ValueError("offset before start")
        if off >= ml:
            out += out[start:start + ml]
        else:
            for k in range(ml):
                out.append(out[start + k])
    return out


def main():
    data = open(sys.argv[1], "rb").read()
    idx = data.find(b"\x02\x21\x4c\x18")
    if idx < 0:
        raise SystemExit("no lz4 legacy magic")
    i = idx + 4
    out = bytearray()
    blocks = 0
    while i + 4 <= len(data):
        bsz = struct.unpack_from("<I", data, i)[0]
        i += 4
        if bsz == 0:
            break
        blk = data[i:i + bsz]
        i += bsz
        if len(blk) != bsz:
            print("short block at end", file=sys.stderr)
            break
        lz4_block(blk, out)
        blocks += 1
    open(sys.argv[2], "wb").write(out)
    print("frame@%#x blocks=%d decoded=%d head=%s magic38=%#x" % (
        idx, blocks, len(out), out[:8].hex(),
        struct.unpack_from("<I", out, 0x38)[0] if len(out) > 0x3c else 0))


if __name__ == "__main__":
    main()
