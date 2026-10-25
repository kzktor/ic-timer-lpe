# dbg_lowL.py -- why the low-L cases fail build_s1's slot uniqueness.
# Offline model only; no device anything.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcastrel4 as M  # noqa: E402


def aux(L):
    base = 0xffffff80036d2000
    out = []
    for k in range(31):
        d = M.KIT * k + M.NODE
        if (d & 0xff) == L:
            out.append((d >> 8, k))
    return out


def chunks_of(rt, L, tsec_bytes):
    pre = M.Block()
    for (r, v, n, tag) in M.field_set(L, rt, 's1'):
        pre.put(r, v, n, 's1.%s' % tag)
    for i in range(M.TSEC_LEN):
        pre.put(rt['sec_res'] + i, tsec_bytes[i], 1, 's1.tsec')
    return pre, M.stage1_kernel(pre.copy(), L, rt)


def main():
    base = 0xffffff80036d2000
    tsec_bytes = b''.join(v.to_bytes(4, 'little')
                          for v in (0x0a, 0x0a, 0, 0, 0, 0))
    for L in (0x18, 0x48):
        for (oi, k) in aux(L):
            X = base + 0x100 * oi + L
            print('== L=%#x O=%d k=%d X=%#x r0=%#x c_lock=%d'
                  % (L, oi, k, X, (L - 0x58) & 0xff,
                     M.chunk_of((L - 0x58) & 0xff)))
            dummy = dict(C=base + 0x18, scratch=0, X=X,
                         wcred=base + 0x838, whead=base + 0x7c8,
                         fake_head=base + 0x08)
            try:
                scratch, sec = next(iter(M.placements(L, dict(dummy,
                                                              scratch=0))))
            except StopIteration:
                print('  no aux placement')
                continue
            st, info = M.L12.solve(base, oi, sec)
            if st is None:
                print('  lay12: no layout at sec=%#x' % sec)
                continue
            C, ci = M.cred_info(st)
            rt = dict(C=C, X=X, winner=0xffffff8001234000,
                      wcred=0xffffff8001234000 + 0x838,
                      whead=0xffffff8001234000 + 0x7c8,
                      elist_head=0xffffff8001234560,
                      C08=0, C10=0, C18=0xffffffff00000000)
            rt['fake_head'] = C - 0x10
            rt = dict(rt, sec_res=sec, scratch_res=scratch,
                      scratch=base + 0x100 * oi + scratch)
            try:
                M.attempt1(base, oi, L, rt, tsec_bytes, scratch, sec)
                print('  OK scratch=%#x sec=%#x C=%#x' % (scratch, sec, C))
                continue
            except M.Fail as e:
                print('  FAIL %s' % e)
            pre, post = chunks_of(rt, L, tsec_bytes)
            a, b = pre.chunks(), post.chunks()
            for i in range(M.NC):
                mark = ''
                if a[i] == bytes(16) or b[i] == bytes(16):
                    mark += ' ZERO'
                for j in range(M.NC):
                    if i != j and (a[j] == a[i] or b[j] == b[i]):
                        mark += ' dup%d%s' % (j, 'P' if a[j] == a[i] else 'T')
                print('  slot %2d pre=%s post=%s%s'
                      % (i, a[i].hex(), b[i].hex(), mark))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
