import sys, random, collections
sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay10 as L

def run(base, oi, sid=1, budget=200000):
    stats = collections.Counter()
    best_depth = 0
    for bC in range(L.NBLK):
        if bC == oi:
            continue
        for pC in range(0x18, 0x49, 8):
            C = base + 0x100 * bC + pC
            s = L.State(base, {oi}).place('cred', C)
            if s is None:
                stats['cred-fail'] += 1
                continue
            stats['cred-ok'] += 1
            s.forbid = {oi, bC}
            # per-object feasibility at this cred placement
            for obj in L.OTHERS:
                if not L.feasible(s, obj):
                    stats['nofeas:' + obj] += 1
            rnd = random.Random(1)
            got = L.dfs(s, list(L.OTHERS), rnd, [budget])
            if got is not None:
                return got, (bC, pC), stats
    return None, None, stats

if __name__ == '__main__':
    base = int(sys.argv[1], 0)
    oi = int(sys.argv[2], 0)
    got, info, st = run(base, oi)
    print('result:', got is not None, info)
    for k, v in st.most_common(20):
        print('   ', v, k)
