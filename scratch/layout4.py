W_LO, W_HI = 0x18, 0xf8
SELF = 'SELF'      # symbolic: cred usage|uid self-pointer
def cred_val(v, s):
    i = s - v
    if i < 0 or i >= 0xb0: return 'OUT'
    if i < 0x04: return SELF
    if i == 0x04: return 0x80   # high half of V: 0xffffff80 low byte
    if i in (0x05,0x06,0x07): return 0xff
    if 0x08 <= i < 0x20: return 0        # gid suid sgid euid egid fsuid
    if 0x20 <= i < 0x24: return 0        # fsgid
    if 0x24 <= i < 0x28: return 'FREE'   # securebits
    if 0x28 <= i < 0x50: return 'FREE'   # caps
    if 0x50 <= i < 0x78: return 0        # 4 keyrings + 8 unknown
    if 0x78 <= i < 0xa0: return ('PTR', (i-0x78)//8)
    return 'FREE'                         # rcu (never freed)
NS = [('uid.nr',0x00,4,1),('uid.first',0x08,4,0),('uid.lower',0x0c,4,0),('uid.count',0x10,4,1),
      ('gid.nr',0x48,4,1),('gid.first',0x50,4,0),('gid.lower',0x54,4,0),('gid.count',0x58,4,1),
      ('parent',0xd8,8,0),('level',0xe0,4,'F'),('owner',0xe8,4,'F'),('group',0xec,4,'F'),
      ('stashed',0xf0,8,'F'),('ops',0xf8,8,0),('inum',0x100,4,'F'),('count',0x104,4,'NZ'),
      ('flags',0x108,4,0),('ucounts',0x210,8,0),('rlimit',0x268,8,'MAX')]
out=[]
for u in range(0x08,0xe8,8):
    for v in range(0x18,0x49,8):
        if v+0xb0 > W_HI: continue
        fixed={}; free=set(); ptrs={}; bad=False
        for s in range(W_LO,W_HI):
            if s >= v and s < v+0xb0:
                x = cred_val(v,s)
                if x=='FREE': free.add(s)
                elif x=='OUT': pass
                else: fixed[s]=x
        # ns fields
        for name,k,sz,nv in NS:
            a=u+k
            for j in range(sz):
                s=(a+j)&0xff; A=a+j
                if a < 0x100 and j==0 or (a<0x100 and a+j<0x100):
                    pass
                if A < 0x100:
                    # direct write in O; only validity check
                    if A < W_LO or A >= W_HI:
                        if not (nv=='F' or (isinstance(nv,int) and nv==0)):
                            bad=True
                    continue
                if s < W_LO or s >= W_HI:
                    if not (nv=='F' or (isinstance(nv,int) and nv==0)):
                        bad=True
                    continue
                if nv=='F':
                    if s not in fixed: free.add(s)
                elif nv=='NZ':
                    if s in fixed:
                        if not (isinstance(fixed[s],int) and 1<=fixed[s]<=0x7e): bad=True
                elif nv=='MAX':
                    if s in fixed: bad=True   # LONG_MAX bytes can't be pre-fixed
                else:
                    if s in fixed and fixed[s]!=nv: bad=True
                    if s in free: free.discard(s)
                    fixed[s]=nv
        if bad: continue
        # windows
        wins=[]
        for k in range(14):
            a=0x18+16*k
            det=[fixed.get(a+i) for i in range(16)]
            zeros = all(x==0 for x in det)
            hasfree = any((a+i) in free for i in range(16))
            wins.append((a,det,zeros,hasfree))
        allzero_nofree = [w for w in wins if w[2] and not w[3]]
        if len(allzero_nofree) > 1: continue
        # duplicate determined nonzero windows?
        seen=set(); dup=False
        for (a,det,zeros,hf) in wins:
            if hf: continue
            t=tuple(det)
            if t in seen: dup=True
            seen.add(t)
        if dup: continue
        # any window with no free byte and not all-zero: value must not collide with... already handled
        # ns.count must be sane: gather its bytes if in F
        # report
        out.append((u,v,[w[0] for w in allzero_nofree]))
print(len(out))
for u,v,az in out[:80]:
    print("u=%#x v=%#x zerowin=%s" % (u,v,[hex(x) for x in az]))
