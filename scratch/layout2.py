# Strict feasibility search: byte-value model over a slot (0x100 offsets).
W_LO, W_HI = 0x18, 0xf8
SELF_LOW, SELF_HIGH = 'SELF_LO', 0xffffff80
P_SEC, P_USER, P_NS, P_UC, P_GI = 'PTR_SEC','PTR_USER','PTR_NS','PTR_UC','PTR_GI'

def cred_bytes(v):
    """byte offset (absolute in slot) -> value; applies to [v, v+0xb0)."""
    b = {}
    b[v+0x00] = SELF_LOW; b[v+0x01]='SELF_1'; b[v+0x02]='SELF_2'; b[v+0x03]='SELF_3'
    for i in (4,5,6,7): b[v+i] = (SELF_HIGH >> (8*(i-4))) & 0xff
    for i in range(0x08, 0x20): b[v+i] = 0          # gid..fsuid
    for i in range(0x20, 0x24): b[v+i] = 0          # fsgid
    for i in range(0x24, 0x28): b[v+i] = None       # securebits free
    for i in range(0x28, 0x50): b[v+i] = None       # caps free
    for i in range(0x50, 0x78): b[v+i] = 0          # keyrings
    for i in range(0x78, 0x80): b[v+i] = P_SEC
    for i in range(0x80, 0x88): b[v+i] = P_USER
    for i in range(0x88, 0x90): b[v+i] = P_NS
    for i in range(0x90, 0x98): b[v+i] = P_UC
    for i in range(0x98, 0xa0): b[v+i] = P_GI
    for i in range(0xa0, 0xb0): b[v+i] = 0
    return b

NS_FIELDS = [  # (k, size, value or None)
    (0x00,4,1), (0x08,4,0), (0x0c,4,0), (0x10,4,1),
    (0x48,4,1), (0x50,4,0), (0x54,4,0), (0x58,4,1),
    (0xd8,8,0), (0xe0,4,None), (0xe8,4,None), (0xec,4,None),
    (0xf0,8,None), (0xf8,8,0), (0x100,4,None), (0x104,4,'NZ'),
    (0x108,4,0), (0x210,8,0), (0x268,8,'MAX'),
]
# Bytes whose content we cannot choose at all.
def unknown_slot_byte(x):
    return (0x00 <= x < 0x08) or (0x08 <= x < 0x18) or (0xf8 <= x < 0x100)

res = []
for u in range(0x10, 0xe8, 8):
    for v in range(0x18, 0x49, 8):
        val = {}            # absolute slot offset -> fixed symbolic value
        known = {}          # offset -> True if bits known from header
        for i in range(0x00, 0x08):
            val[i] = 14 if (i < 4) else 14   # sl_max, sl_count both 14
        cb = cred_bytes(v)
        for x, cv in cb.items():
            if x < W_LO or x >= W_HI: continue
            val[x] = cv
        ok = True
        hard = []   # (abs offset, value) that must hold, from ns direct O writes
        for (k, sz, nv) in NS_FIELDS:
            a = u + k
            for j in range(sz):
                x = a + j
                if x < 0x100:
                    if x < W_LO or x >= W_HI:
                        if nv is not None and not (isinstance(nv,int)):
                            ok = False; break
                        if nv is not None and isinstance(nv,int) and nv != 0:
                            ok = False; break
                        continue
                    continue  # direct write in O
                so = x & 0xff
                if so < W_LO or so >= W_HI:
                    if nv is not None and not isinstance(nv, str):
                        if nv != 0: ok=False; break
                    continue
                # requirement on slot byte so
                if isinstance(nv, str):
                    if nv == 'NZ':
                        # must end up sane positive; if this byte is fixed by cred/header, check
                        if so in val and isinstance(val[so], int):
                            if not (1 <= val[so] <= 0x7f): ok = False; break
                        elif so in val and not isinstance(val[so], int):
                            ok = False; break
                    elif nv == 'MAX':
                        if so in val:
                            if isinstance(val[so], int) and val[so] not in (0,0xff): ok=False; break
                            if not isinstance(val[so], int): ok=False; break
                elif nv is not None:
                    if so in val:
                        if val[so] != nv: ok = False; break
                    # can write it
        if not ok: continue
        # ns count field: all four bytes must form a sane value
        a = u + 0x104
        if a < 0x100:
            pass
        else:
            so = a & 0xff
            if so >= W_HI or so < W_LO: pass
            else:
                vals = [val.get(so+i) for i in range(4)]
                if so+4 <= 0x100:
                    if any(isinstance(x,str) and x not in () for x in vals): ok=False
                if not ok: continue
        res.append((u, v))
print(len(res))
for r in res: print("u=%#x v=%#x" % r)
