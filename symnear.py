#!/usr/bin/env python3
"""Print the nearest preceding kallsyms symbol for each address given.
Usage: python -I symnear.py <kallsyms_py.py> <image> <addr> [addr...]
"""
import sys, importlib.util

ks_path, image_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("kallsyms_py", ks_path)
ks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ks)

image = open(image_path, 'rb').read()
entries, syms = ks.recover(image, None, verbose=False)
entries.sort()
base = next(iter(syms['_text']))
print("_text = %#x  symbols=%d" % (base, len(entries)), file=sys.stderr)

addrs = [int(a, 0) for a in sys.argv[3:]]
for a in addrs:
    prev = None
    nxt = None
    for addr, kind, name in entries:
        if addr <= a:
            prev = (addr, kind, name)
        else:
            nxt = (addr, kind, name)
            break
    if prev:
        print("%#x -> %#x %s (delta %#x)" % (a, prev[0], prev[2], a - prev[0]),
              end="")
    else:
        print("%#x -> <none>" % a, end="")
    if nxt:
        print("   next: %#x %s (delta %#x)" % (nxt[0], nxt[2], nxt[0] - a))
    else:
        print()
