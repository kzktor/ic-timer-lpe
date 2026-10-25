import sys; sys.path.insert(0,'.')
from lay7 import try_layout
WLO,WHI=0x18,0xf8
def ns_direct(u):
    occ=set()
    for a,bs in ((u,[0]*4),(u+0x08,[0]*4),(u+0x0c,[0]*4),(u+0x10,[0]*4),
                 (u+0x48,[0]*4),(u+0x50,[0]*4),(u+0x54,[0]*4),(u+0x58,[0]*4)):
        if a+len(bs) <= 0x100:
            occ.update(range(a,a+len(bs)))
    return occ
def place_fakes(u):
    occ=ns_direct(u)
    Qs=[]
    for Q in range(WLO, 0x100-0x78+1, 8):
        a=set(range(Q+0x10,Q+0x20)) | set(range(Q+0x70,Q+0x78))
        if a & occ: continue
        if not a <= set(range(WLO,WHI)): continue
        Qs.append(Q)
    if not Qs: return None
    Q=Qs[0]
    used=set(occ)|set(range(Q+0x10,Q+0x20))|set(range(Q+0x70,Q+0x78))
    def find(al, size):
        for a in range(WLO, WHI-size+1, al):
            if not (set(range(a,a+size)) & used): return a
        return None
    W=find(4,4)
    if W is None: return None
    used|=set(range(W,W+4))
    GI=find(4,4)
    if GI is None: return None
    used|=set(range(GI,GI+4))
    SEC=find(4,0x18)
    if SEC is None: return None
    used|=set(range(SEC,SEC+0x18))
    return dict(Q=Q,W=W,GI=GI,SEC=SEC)
ok=[]
for v in range(0x18,0x49,8):
    for u in range(0x18,0xe9,8):
        r=try_layout(u,v)
        if r[0]!='OK': continue
        f=place_fakes(u)
        if not f: continue
        ok.append((v,u,r[1],f,sorted(ns_direct(u))))
print("full candidates:",len(ok))
for v,u,z,f,occ in ok:
    print("v=%#x u=%#x zero=%s Q=%#x W=%#x GI=%#x SEC=%#x nsocc=%s" %
          (v,u,[hex(x) for x in z],f['Q'],f['W'],f['GI'],f['SEC'],
           [hex(x) for x in occ]))
