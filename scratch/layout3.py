W_LO, W_HI = 0x18, 0xf8
NS = [
 ('uid.nr',0x00,4,1),('uid.first',0x08,4,0),('uid.lower',0x0c,4,0),('uid.count',0x10,4,1),
 ('gid.nr',0x48,4,1),('gid.first',0x50,4,0),('gid.lower',0x54,4,0),('gid.count',0x58,4,1),
 ('parent',0xd8,8,0),('level',0xe0,4,None),('owner',0xe8,4,None),('group',0xec,4,None),
 ('stashed',0xf0,8,None),('ops',0xf8,8,0),('inum',0x100,4,None),('ns.count',0x104,4,'NZ'),
 ('flags',0x108,4,0),('ucounts',0x210,8,0),('rlimit_max',0x268,8,'MAX'),
]
for (u,v) in [(0x18,0x30),(0x20,0x38),(0x28,0x40),(0x30,0x48)]:
    print("==== u=%#x v=%#x  (cred slot range %#x..%#x)" % (u,v,v,v+0xb0))
    for name,k,sz,nv in NS:
        a=u+k; x=a&0xff
        if a<0x100:
            loc = "O+%#x" % a
            if a < W_LO or a+sz > W_HI: loc += " UNWRITABLE"
        else:
            loc = "F[%#x..%#x) slot %d" % (x,x+sz,a>>8)
            if x < W_LO or x+sz > W_HI: loc += " UNWRITABLE"
            # overlaps cred?
            if not (x+sz <= v or x >= v+0xb0):
                loc += " <-- OVERLAPS CRED off %#x" % (x-v)
        print("   %-10s %s val=%s" % (name, loc, nv))
    print()
