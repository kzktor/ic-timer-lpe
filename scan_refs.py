#!/usr/bin/env python3
"""Scan the raw arm64 kernel image for BL call sites and ADRP/ADD references.

Usage: python -I scan_refs.py IMAGE BASEVA bl <target_va> [<target_va> ...]
       python -I scan_refs.py IMAGE BASEVA adrp <target_va> [<target_va> ...]
"""
import sys
sys.path.insert(0, r"C:\Users\hyw\AppData\Roaming\Python\Python314\site-packages")
import numpy as np

path, base, mode = sys.argv[1], int(sys.argv[2], 0) & (2**64 - 1), sys.argv[3]
targets = [int(t, 0) & (2**64 - 1) for t in sys.argv[4:]]
raw = open(path, "rb").read()
raw = raw[:len(raw) & ~3]
w = np.frombuffer(raw, dtype="<u4")
n = len(w)
baseu = np.uint64(base)


def show(v):
    return int(v) & (2**64 - 1)


if mode == "bl":
    is_bl = (w & np.uint32(0xFC000000)) == np.uint32(0x94000000)
    idx = np.nonzero(is_bl)[0]
    imm = (w[idx] & np.uint32(0x03FFFFFF)).astype(np.int64)
    imm = np.where(imm & 0x02000000, imm - 0x04000000, imm)
    pc = baseu + idx.astype(np.uint64) * np.uint64(4)
    tgt = pc + imm.astype(np.uint64) * np.uint64(4)
    for t in targets:
        for h in idx[tgt == np.uint64(t)]:
            print("bl 0x%x -> 0x%x" % (show(baseu + np.uint64(int(h)) * np.uint64(4)), t))
elif mode == "adrp":
    is_adrp = (w & np.uint32(0x9F000000)) == np.uint32(0x90000000)
    idx = np.nonzero(is_adrp)[0]
    ins = w[idx].astype(np.uint64)
    rd = ins & np.uint64(0x1F)
    immlo = (ins >> np.uint64(29)) & np.uint64(0x3)
    immhi = (ins >> np.uint64(5)) & np.uint64(0x7FFFF)
    imm = (immhi << np.uint64(2)) | immlo
    neg = (imm & np.uint64(0x100000)) != 0
    imm_s = np.where(neg, imm.astype(np.int64) - 0x200000, imm.astype(np.int64))
    pc = baseu + idx.astype(np.uint64) * np.uint64(4)
    page = (pc & np.uint64(2**64 - 0x1000)) + imm_s.astype(np.uint64) * np.uint64(4096)
    for t in targets:
        tp = t & ~0xFFF
        sel = np.nonzero(page == np.uint64(tp))[0]
        for j in sel:
            h = int(idx[j])
            addimm = t & 0xFFF
            for k in range(0, 6):
                x = int(w[h + k]) & 0xFFFFFFFF
                if (x & 0xFF800000) == 0x91000000 and ((x >> 5) & 0x1F) == int(rd[j]) \
                        and ((x >> 10) & 0xFFF) == addimm and (x & 0x1F) == int(rd[j]):
                    print("adrp/add 0x%x (adrp at 0x%x) -> 0x%x" %
                          (show(baseu + np.uint64((h + k) * 4)),
                           show(baseu + np.uint64(h * 4)), t))
                    break
else:
    raise SystemExit("mode?")
