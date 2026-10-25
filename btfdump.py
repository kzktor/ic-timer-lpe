#!/usr/bin/env python3
"""Minimal BTF reader: dump struct/union member offsets by name.

Usage: python -I btfdump.py FILE.btf STRUCT [MEMBER...]
       python -I btfdump.py FILE.btf --size STRUCT [MEMBER...]
"""
import struct
import sys

path = sys.argv[1]
want = sys.argv[2:]
show_size = False
if want and want[0] == "--size":
    show_size = True
    want = want[1:]

d = open(path, "rb").read()
magic, ver, flags, hlen, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", d, 0)
assert magic == 0xEB9F, hex(magic)
tb = hlen + toff
te = tb + tlen
sb = hlen + soff
strs = d[sb:sb + slen]

def s(off):
    if off == 0:
        return ""
    e = strs.find(b"\0", off)
    return strs[off:e].decode("utf-8", "replace")

KIND = {1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION", 6: "ENUM",
        7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST", 11: "RESTRICT",
        12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC", 16: "FLOAT",
        17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64"}

types = [None]  # 1-based
p = tb
while p < te:
    name_off, info, size_type = struct.unpack_from("<III", d, p)
    p += 12
    kind = (info >> 24) & 0x1F
    vlen = info & 0xFFFF
    kflag = info >> 31
    name = s(name_off)
    extra = b""
    if kind in (4, 5):
        extra = d[p:p + vlen * 12]
        p += vlen * 12
    elif kind == 3:
        extra = d[p:p + 12]
        p += 12
    elif kind == 1:
        p += 4
    elif kind == 6:
        p += vlen * 8
    elif kind == 13:
        p += vlen * 8
    elif kind == 14:
        p += 4
    elif kind == 15:
        p += vlen * 12
    elif kind == 17:
        p += 8
    elif kind == 19:
        p += vlen * 12
    types.append((name, kind, vlen, kflag, size_type, extra))

names = set(want)
for idx, t in enumerate(types):
    if not t:
        continue
    name, kind, vlen, kflag, size_type, extra = t
    if name not in names or kind not in (4, 5):
        continue
    print("== %s %s id=%d size=%d kflag=%d" %
          (KIND[kind], name, idx, size_type, kflag))
    for i in range(vlen):
        moff, mtype, mbit = struct.unpack_from("<III", extra, i * 12)
        if kflag:
            boff = mbit & 0xFFFFFF
            bsz = mbit >> 24
        else:
            boff = mbit
            bsz = 0
        print("  +0x%03x %-32s type=%d bits=%d" %
              (boff // 8, s(moff), mtype, bsz))
