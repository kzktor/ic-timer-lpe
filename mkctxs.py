#!/usr/bin/env python3
"""Build a list of SELinux contexts to intern before the sid scan.

The kernel only assigns a sid to a context the first time it interns it;
a minimal guest never touches system domains, so their sids do not exist
and the scan cannot reach them.  Writing each context to
/sys/fs/selinux/context while the policy is still permissive allocates
the sid without changing our own.

Usage: mkctxs.py <plat.cil> <out.txt>
"""
import re
import sys

def main():
    src, dst = sys.argv[1], sys.argv[2]
    domains = []
    objects = []
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"\(typeattributeset domain \((.*)\)\)\s*$", line)
            if m:
                domains.extend(m.group(1).split())
                continue
            m = re.match(r"\(roletype object_r ([A-Za-z0-9_]+)\)\s*$", line)
            if m:
                objects.append(m.group(1))
    # Only domains matter: the scan forks under the candidate sid, and an
    # object type has no self-fork allow.  Each interned context costs one
    # audited (permissive) denial on the serial console, so skip objects.
    ctxs = ["u:r:%s:s0" % t for t in domains]
    # newline="\n": the guest sees these bytes verbatim, and a stray \r
    # turns "adbd" into a type name that does not exist.
    with open(dst, "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(ctxs) + "\n")
    print("domains=%d objects=%d total=%d" % (len(domains), len(objects), len(ctxs)))

main()
