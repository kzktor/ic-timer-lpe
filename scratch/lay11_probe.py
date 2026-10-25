# lay11_probe -- is a given object placement even *possible* (per-object
# feasibility), and does a cred/ns pair exist at all?  Fast diagnostics
# before running the full DFS.
import sys, collections
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay11 as L


def main():
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    oi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 11
    stats = collections.Counter()
    pair_hits = 0
    example = None
    for bC in range(L.NBLK):
        if bC == oi:
            continue
        for pC in range(0x00, 0x100, 8):
            C = base + 0x100 * bC + pC
            s = L.State(base, {oi}).place('cred', C)
            if s is None:
                stats['cred-fail'] += 1
                continue
            stats['cred-ok'] += 1
            s.forbid = {oi, bC}
            if not L.feasible(s, 'ns'):
                stats['nofeas:ns'] += 1
                continue
            pair_hits += 1
            if example is None:
                # show where the ns can go
                fs = L.feasible(s, 'ns')
                example = (bC, pC, fs[:4], len(fs))
            for obj in L.OTHERS:
                if not L.feasible(s, obj):
                    stats['nofeas:' + obj] += 1
    print('base=%#x oi=%d' % (base, oi))
    print('cred/ns-compatible placements:', pair_hits)
    for k, v in stats.most_common(20):
        print('   ', v, k)
    if example:
        print('example cred=(%d,%#x) ns choices=%d first=%s'
              % (example[0], example[1], example[3],
                 [('b%d' % b, '%#x' % p) for b, p in example[2]]))


if __name__ == '__main__':
    main()
