# gen_mcast_tables.py -- emit the D2 psl patterns as C tables.
#
# Every pattern is a set of 14 16-byte source addresses.  A byte is either a
# literal or one byte of an 8-byte word equal to (slab_base + off) or
# (winner + off); 8-byte fields never straddle a 16-byte source slot.  The
# relocation is derived by rebuilding each image with a shifted base and a
# shifted winner and diffing, so the tables cannot drift from the model.
import sys

sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import lay12 as L12
import mcastrel4 as M

S0 = 0xffffff80036d2000
DS = 0x2000
W0 = 0xffffff8001234000
DW = 0x10000
TSEC = b''.join(v.to_bytes(4, 'little') for v in (0x0a, 0x0a, 0, 0, 0, 0))


def addr_offsets(st, base):
    return {k: v - base for k, v in st.addr.items()}


def base_chunks(base, oi, sec):
    st, info = L12.solve(base, oi, sec)
    assert st is not None, 'solve failed'
    return L12.chunks_of(st.mem), addr_offsets(st, base)


def s1_chunks(base, oi, L, C_off, scratch_res, sec, winner):
    X = base + 0x100 * oi + L
    C = base + C_off
    rt = dict(C=C, X=X,
              scratch=base + 0x100 * oi + scratch_res,
              fake_head=C - 0x10, sec_res=sec,
              elist_head=X + 0x30, winner=winner,
              wcred=winner + 0x838, whead=winner + 0x7c8,
              C08=0, C10=0, C18=0xffffffff00000000)
    pre, post = M.build_s1(L, rt, TSEC)
    return pre.chunks(), post.chunks()


def s2_chunks(base, oi, L, C_off, scratch_res, sec, winner):
    X = base + 0x100 * oi + L
    C = base + C_off
    rt = dict(C=C, X=X,
              scratch=base + 0x100 * oi + scratch_res,
              fake_head=C - 0x10, sec_res=sec,
              elist_head=X + 0x30, winner=winner,
              wcred=winner + 0x838, whead=winner + 0x7c8,
              C08=0, C10=0, C18=0xffffffff00000000)
    return M.build(L, rt, 's2', TSEC).chunks()


def reloc(chunks_a, chunks_b, chunks_c, base_a, base_b, win_a, win_c):
    """Per chunk: lit bytes + up to two 8-byte relocations.

    chunks_a: (base_a, win_a); chunks_b: (base_b, win_a); chunks_c:
    (base_a, win_c).  A word that follows base is (kind 1, off = v - base_a);
    a word that follows winner is (kind 2, off = v - win_a)."""
    out = []
    for k in range(14):
        lit = bytearray(chunks_a[k])
        rels = []
        for i in (0, 8):
            w0 = int.from_bytes(chunks_a[k][i:i + 8], 'little')
            wb = int.from_bytes(chunks_b[k][i:i + 8], 'little')
            wc = int.from_bytes(chunks_c[k][i:i + 8], 'little')
            if w0 == wb == wc:
                continue
            if wb == w0 + (base_b - base_a) and wc == w0:
                rels.append((i, 1, (w0 - base_a) & 0xffffffffffffffff))
            elif wc == w0 + (win_c - win_a) and wb == w0:
                rels.append((i, 2, (w0 - win_a) & 0xffffffffffffffff))
            else:
                raise SystemExit('chunk %d +%d: not a pure relocation '
                                 '(%#x %#x %#x)' % (k, i, w0, wb, wc))
        for (i, kind, off) in rels:
            for j in range(8):
                lit[i + j] = 0
        out.append((bytes(lit), rels))
    return out


def emit_tab(name, cases):
    print('static const struct ic_mcast_pat %s[] = {' % name)
    for c in cases:
        print('\t{')
        for k, (lit, rels) in enumerate(c['chunks']):
            r = ['%d, %d' % (0, 0)] * 2
            o = ['0', '0']
            for i, kind, off in rels:
                r[i // 8] = '%d, %d' % (kind, 0)
                o[i // 8] = '0x%x' % off
            print('\t\t{ { %s }, { %s }, { %s } }, /* %d */'
                  % (', '.join('0x%02x' % b for b in lit),
                     ', '.join('%d' % kk for kk in
                               (rels[0][1] if len(rels) > 0 else 0,
                                rels[1][1] if len(rels) > 1 else 0)),
                     ', '.join(o), k))
        print('\t},')
    print('};')


def main():
    cases = []
    # X = S + 0x108k + 0x78: O and L are both functions of k.
    for k in range(31):
        d = 0x108 * k + 0x78
        L = d & 0xff
        oi = d >> 8
        if L not in M.CLEAN_L:
            continue
        dummy = dict(C=S0 + 0x18, scratch=0, X=S0 + 0x100 * oi + L,
                     wcred=W0 + 0x838, whead=W0 + 0x7c8,
                     fake_head=S0 + 0x08)
        got = None
        for scratch, sec in M.placements(L, dict(dummy, scratch=0)):
            try:
                base0, off0 = base_chunks(S0, oi, sec)
                base1, off1 = base_chunks(S0 + DS, oi, sec)
                assert off0 == off1, 'layout depends on the base'
                C_off = off0['cred']
                s1a, _ = s1_chunks(S0, oi, L, C_off, scratch, sec, W0)
                s1b, _ = s1_chunks(S0 + DS, oi, L, C_off, scratch, sec, W0)
                s1c, _ = s1_chunks(S0, oi, L, C_off, scratch, sec, W0 + DW)
                s2a = s2_chunks(S0, oi, L, C_off, scratch, sec, W0)
                s2b = s2_chunks(S0 + DS, oi, L, C_off, scratch, sec, W0)
                s2c = s2_chunks(S0, oi, L, C_off, scratch, sec, W0 + DW)
            except (M.Fail, AssertionError):
                continue
            got = (scratch, sec, C_off, base0, base1, s1a, s1b, s1c,
                   s2a, s2b, s2c)
            break
        if got is None:
            raise SystemExit('O=%d L=%#x: no placement builds' % (oi, L))
        (scratch, sec, C_off, base0, base1, s1a, s1b, s1c,
         s2a, s2b, s2c) = got
        r0 = (L - 0x58) & 0xff
        cases.append(dict(
            oi=oi, L=L, r0=r0, c_lock=M.chunk_of(r0), sec=sec,
            scratch=scratch, C_off=C_off,
            base=reloc(base0, base1, base0, S0, S0 + DS, W0, W0),
            s1=reloc(s1a, s1b, s1c, S0, S0 + DS, W0, W0 + DW),
            s2=reloc(s2a, s2b, s2c, S0, S0 + DS, W0, W0 + DW)))
        print('/* O=%d L=0x%02x scratch=0x%02x tsec=0x%02x cred=0x%x */'
              % (oi, L, scratch, sec, C_off), file=sys.stderr)

    hdr = []
    hdr.append('/* generated by gen_mcast_tables.py -- do not edit */')
    hdr.append('#define IC_MC_CASES %d' % len(cases))
    hdr.append('')
    hdr.append('struct ic_mcast_chunk {')
    hdr.append('\tuint8_t lit[16];')
    hdr.append('\tuint8_t rel[2];   /* 0 literal, 1 slab, 2 winner */')
    hdr.append('\tuint32_t off[2];')
    hdr.append('};')
    hdr.append('')
    hdr.append('struct ic_mcast_pat {')
    hdr.append('\tstruct ic_mcast_chunk c[14];')
    hdr.append('};')
    hdr.append('')
    hdr.append('struct ic_mcast_case {')
    hdr.append('\tuint8_t oi, l, r0, c_lock, sec, scratch;')
    hdr.append('\tuint32_t cred_off;')
    hdr.append('\tstruct ic_mcast_pat base, s1, s2;')
    hdr.append('};')
    hdr.append('')
    print('\n'.join(hdr))
    print('static const struct ic_mcast_case ic_mcast_cases[] = {')
    for c in cases:
        print('\t{ %d, 0x%02x, 0x%02x, %d, 0x%02x, 0x%02x, 0x%x,'
              % (c['oi'], c['L'], c['r0'], c['c_lock'], c['sec'],
                 c['scratch'], c['C_off']))
        for nm in ('base', 's1', 's2'):
            # Two braces: one for struct ic_mcast_pat, one for its c[14].
            # With a single brace the compiler takes it as the brace of c[]
            # and the first chunk's brace as c[0], so the whole pattern is
            # silently mis-nested.
            print('\t  { /* %s */ {' % nm)
            for (lit, rels) in c[nm]:
                r = [0, 0]
                o = [0, 0]
                for i, kind, off in rels:
                    r[i // 8] = kind
                    o[i // 8] = off
                print('\t    { { %s }, { %d, %d }, { 0x%x, 0x%x } },'
                      % (', '.join('0x%02x' % b for b in lit), r[0], r[1],
                         o[0], o[1]))
            print('\t  } },')
        print('\t},')
    print('};')
    return 0


if __name__ == '__main__':
    sys.exit(main())
