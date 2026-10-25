#!/usr/bin/env python3
"""Pagetype-vector digest for the IC_PAGEPROBE run.

Parses lines of the form

  [reap] ptv@<tag> <Type> v0,v1,...,v10 tot=<pages>

(printed by ic_pagetype_stat() when IC_PTVEC is set) and reports, for each
probe primitive, the per-migratetype / per-order block delta between the
primitive's -pre and -post snapshots.  A block at order o is 2^o pages, so
the "pages" column is the actual consumption.  Stdlib only, read-only.
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "pp_probe1.log"
lines = open(path, errors="replace").read().splitlines()

pat = re.compile(r"ptv@(\S+)\s+(\S+)\s+([\d,]+)(?:\s+tot=(\d+))?")
stats = {}
order_of = []
for ln in lines:
    m = pat.search(ln)
    if not m:
        continue
    tag, typ, vec, tot = m.group(1), m.group(2), m.group(3), m.group(4)
    try:
        v = [int(x) for x in vec.split(",")]
    except ValueError:
        continue
    stats.setdefault(tag, {})[typ] = (v, int(tot) if tot else sum(
        b << o for o, b in enumerate(v)))
    if typ == "Unmovable" and len(v) > len(order_of):
        order_of = v

pairs = [
    ("anon", "anon-pre", "anon-post"),
    ("pte", "pte-pre", "pte-post"),
    ("skb", "skb-pre", "skb-post"),
    ("aio", "aio-pre", "aio-post"),
    ("perf", "perf-pre", "perf-post"),
    ("pkt", "pkt-pre", "pkt-post"),
    ("pipe", "pipe-pre", "pipe-post"),
    ("uring", "uring-pre", "uring-post"),
    ("uring-free", "uring-post", "uring-free"),
]

types = ["Unmovable", "Movable", "Reclaimable", "CMA", "HighAtomic",
         "RSCIS", "RSCIB", "ThpPool", "Isolate"]


def show(tag_a, tag_b, name):
    a = stats.get(tag_a, {})
    b = stats.get(tag_b, {})
    if not a or not b:
        print(f"== {name}: missing {tag_a if not a else tag_b} ==")
        return
    print(f"== {name}: {tag_a} -> {tag_b} ==")
    for t in types:
        if t not in a and t not in b:
            continue
        va, ta = a.get(t, ([0] * 11, 0))
        vb, tb = b.get(t, ([0] * 11, 0))
        dv = [vb[i] - va[i] for i in range(len(va))]
        changed = [(i, d) for i, d in enumerate(dv) if d]
        if not changed and ta == tb:
            continue
        parts = []
        pages = 0
        for i, d in changed:
            parts.append(f"o{i}{d:+d}")
            pages += d << i
        print(f"  {t:12s} dtotal={tb - ta:+8d} pages~{pages:+8d}  "
              + " ".join(parts))
    print()


for name, pa, pb in pairs:
    show(pa, pb, name)
