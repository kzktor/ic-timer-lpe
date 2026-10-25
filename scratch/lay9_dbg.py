# Diagnose lay9: where does the greedy placement fail?
import random, sys, collections
sys.path.insert(0, r'D:\kwork\icbuild\scratch')   # own analysis dir
import lay9
from lay9 import Layout, ORDER, WLO, WHI

def run(base, oi, trials=2000, seed=7):
    rnd = random.Random(seed)
    phases = list(range(WLO, 0xf0, 8))
    forbidden = (oi, oi + 1)
    fail = collections.Counter()
    stage_fail = collections.Counter()
    for t in range(trials):
        cred_block = rnd.choice([b for b in range(32) if b not in forbidden])
        cred_phase = rnd.choice(list(range(WLO, 0x49, 8)))
        C = base + 0x100 * cred_block + cred_phase
        lay = Layout(base, 1)
        lay.addr['cred'] = C
        for obj in ORDER:
            cands = [(base + 0x100 * b + p) for b in range(32) for p in phases]
            rnd.shuffle(cands)
            nfail = 0
            done = False
            for a in cands:
                if lay.place(obj, a, forbidden):
                    done = True
                    break
                nfail += 1
            if not done:
                fail[obj] += 1
                stage_fail[(obj, tuple(o for o in ORDER[:ORDER.index(obj)]))] += 1
                break
        else:
            if not lay.place('cred', C, forbidden):
                fail['cred'] += 1
                continue
            chk = lay.check_chain()
            if all(v for _, v in chk):
                return 'OK', lay, t
            fail['chain:' + ','.join(k for k, v in chk if not v)] += 1
    return 'FAIL', fail, -1

if __name__ == '__main__':
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xffffff80036d2000
    oi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 11
    st, info, t = run(base, oi)
    print(st, t)
    if st == 'FAIL':
        for k, v in info.most_common(20):
            print('  ', v, k)
