# lay11_one -- run the DFS for one (or a few) cred placements, report timing.
import sys, time, random
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    oi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 11
    limit = int(sys.argv[3], 0) if len(sys.argv) > 3 else 8
    budget = int(sys.argv[4], 0) if len(sys.argv) > 4 else 200000
    n = 0
    t0 = time.time()
    for bC in range(L.NBLK):
        if bC == oi:
            continue
        for pC in range(0x00, 0x100, 8):
            C = base + 0x100 * bC + pC
            s = L.State(base, {oi}).place('cred', C)
            if s is None:
                continue
            s.forbid = {oi, bC}
            rnd = random.Random(1 ^ (bC << 8) ^ pC)
            t = time.time()
            got = L.dfs(s, list(L.OTHERS), rnd, [budget])
            n += 1
            print('cred=(%2d,%#04x) %s  %.1fs' %
                  (bC, pC, 'OK' if got else 'no', time.time() - t))
            if got is not None:
                mem = L.fill_chunks(got.mem)
                print('fill_chunks:', 'ok' if mem is not None else 'NONE')
                if mem is not None:
                    got.mem = mem
                L.dump(got, 'LAYOUT')
                for i, c in enumerate(L.chunks_of(got.mem)):
                    print('   [%2d] %s' % (i, c.hex()))
                return 0
            if n >= limit:
                print('total %.1fs' % (time.time() - t0))
                return 1
    print('total %.1fs' % (time.time() - t0))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
