# print BTF type id -> kind/name (quick resolver)
import struct, sys
d = open(sys.argv[1], "rb").read()
magic, ver, flags, hlen, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", d, 0)
assert magic == 0xEB9F
tb = hlen + toff; te = tb + tlen
sb = hlen + soff; strs = d[sb:sb + slen]
def s(off):
    if off == 0: return ""
    e = strs.find(b"\0", off)
    return strs[off:e].decode("utf-8", "replace")
KIND = {1:"INT",2:"PTR",3:"ARRAY",4:"STRUCT",5:"UNION",6:"ENUM",7:"FWD",8:"TYPEDEF",9:"VOLATILE",10:"CONST",11:"RESTRICT",12:"FUNC",13:"FUNC_PROTO",14:"VAR",15:"DATASEC",16:"FLOAT",17:"DECL_TAG",18:"TYPE_TAG",19:"ENUM64"}
types = [None]; p = tb
while p < te:
    no, info, st = struct.unpack_from("<III", d, p); p += 12
    kind = (info >> 24) & 0x1F; vlen = info & 0xFFFF; kflag = info >> 31
    extra = b""
    if kind in (4,5): extra = d[p:p+vlen*12]; p += vlen*12
    elif kind == 3: extra = d[p:p+12]; p += 12
    elif kind == 1: p += 4
    elif kind == 6: p += vlen*8
    elif kind == 13: p += vlen*8
    elif kind == 14: p += 4
    elif kind == 15: p += vlen*12
    elif kind == 17: p += 8
    elif kind == 19: p += vlen*12
    types.append((s(no), kind, vlen, kflag, st, extra))
for a in sys.argv[2:]:
    i = int(a, 0)
    if 0 < i < len(types):
        n, k, v, kf, st, ex = types[i]
        print('%6d %-10s %-28s size/type=%d vlen=%d' % (i, KIND.get(k, k), n, st, v))
