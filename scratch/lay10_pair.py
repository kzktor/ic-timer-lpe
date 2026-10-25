import sys
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay10 as L

WLO, WHI = L.WLO, L.WHI

def fixed_bytes(obj, A):
    """residue -> byte for the int-literal fields only (pointers ignored)."""
    m = {}
    for (off, size, spec) in L.OBJS[obj]:
        if not isinstance(spec, int):
            continue
        for i in range(size):
            r = (A + off + i) & 0xff
            m[r] = (spec >> (8 * i)) & 0xff
    return m

def window_ok(obj, A):
    for (off, size, spec) in L.OBJS[obj]:
        if spec is None:
            continue
        for i in range(size):
            r = (A + off + i) & 0xff
            if not (WLO <= r < WHI):
                return False, ('off', off, i, r)
    return True, None

base = 0xffffff80036d2000
good = 0
for bC in range(32):
    for pC in range(0x18, 0x49, 8):
        C = base + 0x100 * bC + pC
        mC = fixed_bytes('cred', C)
        # cred self pointer
        for i in range(8):
            mC[pC + i] = (C >> (8 * i)) & 0xff
        for bN in range(32):
            for pN in range(0x18, 0xf0, 8):
                U = base + 0x100 * bN + pN
                okw, why = window_ok('ns', U)
                if not okw:
                    continue
                mN = fixed_bytes('ns', U)
                bad = [r for r in mC if r in mN and mC[r] != mN[r]]
                if not bad:
                    good += 1
                    if good <= 5:
                        print('pair cred(%d,%#x) ns(%d,%#x)' % (bC, pC, bN, pN))
print('total compatible cred/ns placements (fixed bytes + window):', good)
