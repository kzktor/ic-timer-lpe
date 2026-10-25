# lay11_sweep -- for every possible node block O (the leak determines it at
# runtime), find at least one full uniform-pattern layout.  The runtime then
# only has to substitute slab_base into the placement table.
import sys, time, random
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L


def one(base, oi, limit, budget):
    t0 = time.time()
    n = 0
    for bC in range(L.NBLK):
        if bC == oi:
            continue
        for pC in range(0x18, 0x49, 8):
            C = base + 0x100 * bC + pC
            s = L.State(base, {oi}).place('cred', C)
            if s is None:
                continue
            s.forbid = {oi, bC}
            rnd = random.Random(0x5a1 + (bC << 8) + pC)
            got = L.dfs(s, list(L.OTHERS), rnd, [budget])
            n += 1
            if got is None:
                continue
            mem = L.fill_chunks(got.mem)
            if mem is None:
                continue
            got.mem = mem
            ch = L.chunks_of(got.mem)
            if len(set(ch)) != 14:
                continue
            return got, (bC, pC), n, time.time() - t0
    return None, None, n, time.time() - t0


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    limit = int(sys.argv[2], 0) if len(sys.argv) > 2 else 400
    budget = int(sys.argv[3], 0) if len(sys.argv) > 3 else 60000
    ois = [int(x, 0) for x in sys.argv[4:]] or list(range(L.NBLK))
    for oi in ois:
        got, info, n, dt = one(base, oi, limit, budget)
        if got is None:
            print('O=%2d  NO (tried %d, %.1fs)' % (oi, n, dt))
        else:
            print('O=%2d  ok cred=(%2d,%#04x) %s tries=%d %.2fs'
                  % (oi, info[0], info[1],
                     ' '.join('%s@%d/%#x' % (o, (got.addr[o] - base) >> 8,
                                             got.addr[o] & 0xff)
                              for o in ['ns', 'ucounts', 'user', 'gi', 'sec']),
                     n, dt))
        sys.stdout.flush()


if __name__ == '__main__':
    main()
