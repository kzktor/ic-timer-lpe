#!/usr/bin/env python3
"""Summarize IC_DRAIN snapshots: where did the drained pages come from?

Reads [reap] ptv@<tag> <Type> v0..v10 tot=<pages> lines emitted by
ic_pagetype_stat() when IC_PTVEC is set, prints for every snapshot the
Unmovable / RSCIS / RSCIB vector, and shows the cumulative delta against
the drain-pre baseline for each migratetype.
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "drain_pipe1.log"
lines = open(path, errors="replace").read().splitlines()

pat = re.compile(r"ptv@(\S+)\s+(\S+)\s+([\d,]+)(?:\s+tot=(\d+))?")
snaps = []
for ln in lines:
    m = pat.search(ln)
    if not m:
        continue
    tag, typ, vec, tot = m.group(1), m.group(2), m.group(3), m.group(4)
    try:
        v = [int(x) for x in vec.split(",")]
    except ValueError:
        continue
    if not snaps or snaps[-1][0] != tag:
        snaps.append((tag, {}))
    snaps[-1][1][typ] = (v, int(tot) if tot else sum(b << o for o, b in enumerate(v)))

types = ["Unmovable", "Movable", "Reclaimable", "CMA", "HighAtomic",
         "RSCIS", "RSCIB", "ThpPool", "Isolate"]

def fmt(v):
    return ",".join(str(x) for x in v)

base = None
prev = None
for tag, d in snaps:
    u = d.get("Unmovable", ([0] * 11, 0))
    rs = d.get("RSCIS", ([0] * 11, 0))
    rb = d.get("RSCIB", ([0] * 11, 0))
    line = f"{tag:12s} u={fmt(u[0]):26s}({u[1]:7d}) rs={rs[1]:7d} rb={rb[1]:7d}"
    if base is None:
        base = d
    else:
        ds = []
        for t in types:
            a = base.get(t, ([0] * 11, 0))[1]
            b = d.get(t, ([0] * 11, 0))[1]
            if b != a:
                ds.append(f"{t[:4]}{b - a:+d}")
        line += "  d/base " + " ".join(ds)
    if prev is not None:
        du = [u[0][i] - prev.get("Unmovable", ([0] * 11, 0))[0][i]
              for i in range(len(u[0]))]
        ch = [f"o{i}{x:+d}" for i, x in enumerate(du) if x]
        if ch:
            line += "  dU " + " ".join(ch)
    print(line)
    prev = d
