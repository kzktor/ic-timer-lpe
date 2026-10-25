# verify_tables.py -- check that mcast_pats.h expands to the model images.
#
# Parses the emitted C tables (lit/rel/off per chunk), expands them for a
# concrete slab base and winner, and compares against the images that
# gen_mcast_tables.py builds directly from the model.  Catches emission
# bugs (brace nesting, kind/off mixups) that would otherwise only show up
# as a dead QEMU run.
import re
import sys

sys.path.insert(0, r'D:\kwork\icbuild\scratch')
import gen_mcast_tables as G
import mcastrel4 as M

HDR = r'D:\kwork\icbuild\mcast_pats.h'
S0 = 0xffffff80036d2000
W0 = 0xffffff8001234000


def parse_header(path):
    txt = open(path).read()
    txt = re.sub(r'/\*[^*]*\*/', '', txt)
    body = txt[txt.index('ic_mcast_cases[] = {'):]
    # case header line: "{ oi, l, r0, c_lock, sec, scratch, cred_off,"
    head_re = re.compile(
        r'\{\s*(\d+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(\d+),\s*'
        r'(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),')
    chunk_re = re.compile(
        r'\{\s*\{\s*(0x[0-9a-f]{2}(?:,\s*0x[0-9a-f]{2}){15})\s*\},\s*'
        r'\{\s*(\d+),\s*(\d+)\s*\},\s*'
        r'\{\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\s*\}\s*\}')
    marks = [(m.end(), m.groups()) for m in head_re.finditer(body)]
    out = []
    for ci, (pos, h) in enumerate(marks):
        end = marks[ci + 1][0] if ci + 1 < len(marks) else len(body)
        chunks = chunk_re.findall(body[pos:end])
        assert len(chunks) == 42, (ci, len(chunks))
        pats = []
        for pi in range(3):
            pat = []
            for c in chunks[pi * 14:pi * 14 + 14]:
                lit = [int(x, 0) for x in c[0].split(',')]
                assert len(lit) == 16, lit
                pat.append((bytes(lit), [int(c[1]), int(c[2])],
                            [int(c[3], 0), int(c[4], 0)]))
            pats.append(pat)
        out.append((dict(oi=int(h[0]), l=int(h[1], 0), r0=int(h[2], 0),
                         c_lock=int(h[3]), sec=int(h[4], 0),
                         scratch=int(h[5], 0), cred_off=int(h[6], 0)),
                    pats))
    return out


def expand(pat, slab, winner):
    img = []
    for (lit, rel, off) in pat:
        b = bytearray(lit)
        for i in (0, 8):
            k = rel[i // 8]
            if k == 1:
                b[i:i + 8] = ((slab + off[i // 8]) & (2**64 - 1)).to_bytes(8, 'little')
            elif k == 2:
                b[i:i + 8] = ((winner + off[i // 8]) & (2**64 - 1)).to_bytes(8, 'little')
            else:
                assert k == 0
        img.append(bytes(b))
    return img


def model(cs):
    base, off = G.base_chunks(S0, cs['oi'], cs['sec'])
    s1a, _ = G.s1_chunks(S0, cs['oi'], cs['l'], cs['cred_off'],
                         cs['scratch'], cs['sec'], W0)
    s2 = G.s2_chunks(S0, cs['oi'], cs['l'], cs['cred_off'],
                     cs['scratch'], cs['sec'], W0)
    return base, s1a, s2


def main():
    tabs = parse_header(HDR)
    print('cases in header:', len(tabs))
    ok = 0
    for cs, pats in tabs:
        mb, m1, m2 = model(cs)
        for name, got, want in (('base', pats[0], mb), ('s1', pats[1], m1),
                                ('s2', pats[2], m2)):
            e = expand(got, S0, W0)
            if e != list(want):
                for i, (a, b) in enumerate(zip(e, want)):
                    if a != b:
                        print('MISMATCH O=%d L=%#x %s chunk %d\n  hdr %s\n'
                              '  mod %s' % (cs['oi'], cs['l'], name, i,
                                            a.hex(), b.hex()))
                return 1
        ok += 1
        print('O=%d L=0x%02x ok (base/s1/s2)' % (cs['oi'], cs['l']))
    print('%d/%d cases match the model' % (ok, len(tabs)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
