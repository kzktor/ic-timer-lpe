#!/usr/bin/env python3
# P2c log digest: pad-drop -> pre-spray -> post-spray deltas for the caches
# that can steal the freed posix_timers block, plus the per-order Unmovable
# free-page vector and the chain outcome.  Pure stdlib, read-only.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "mrgP2c_diag.log"
lines = open(path, errors="replace").read().splitlines()

cache_re = re.compile(r"cache@(\S+)\s+(\S+):(.*)")
pt_re = re.compile(r"pt@(\S+)\s+:\s+u=(\S+)")
kv_re = re.compile(r"(\w+)=(\d+)")
wanted = ["vm_area_struct", "maple_node", "filp", "dentry", "kioctx",
          "inode_cache", "lsm_inode_cache", "posix_timers_cache", "anon_vma",
          "cred_jar", "kmalloc-256"]

stats = {}   # (tag, cache) -> dict
pts = {}     # tag -> u vector
outcome = []
spray = None
for ln in lines:
    m = cache_re.search(ln)
    if m:
        tag, cache, rest = m.group(1), m.group(2), m.group(3)
        stats[(tag, cache)] = dict(kv_re.findall(rest))
        continue
    m = pt_re.search(ln)
    if m:
        pts[m.group(1)] = m.group(2)
        continue
    for key in ("[peak] LEAK", "[peak] no leak", "spray pages",
                "Kernel panic", "stage1", "stage2", "setresuid",
                "[helper] launched", "spray failed"):
        if key in ln:
            outcome.append(ln.strip())

print("== outcome ==")
for o in outcome:
    print(o)

print("\n== Unmovable free blocks per order (u=o0,o1,...) ==")
for tag in ("pad-drop", "pre-spray", "post-spray"):
    if tag in pts:
        print(f"{tag:10s} {pts[tag]}")

print("\n== cache objects/slabs pre-spray -> post-spray ==")
for c in wanted:
    a = stats.get(("pre-spray", c))
    b = stats.get(("post-spray", c))
    if not a and not b:
        continue
    def fmt(d):
        if not d:
            return "?"
        return f"obj={d.get('objects','?'):>6} slabs={d.get('slabs','?'):>4} part={d.get('partial','?'):>4}"
    dl = ""
    if a and b and "slabs" in a and "slabs" in b:
        try:
            dl = f"  dslabs={int(b['slabs']) - int(a['slabs']):+d}"
        except ValueError:
            pass
    print(f"{c:18s} pre[{fmt(a)}]  post[{fmt(b)}]{dl}")
