#!/usr/bin/env python3
"""Dump selected symbols from a vmlinux image using the ghostlock recovery code.

Usage: python -I symdump.py <kallsyms_py.py> <image> <name> [<name> ...]
"""
import importlib.util
import sys


def main():
    spec = importlib.util.spec_from_file_location("ks", sys.argv[1])
    ks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ks)
    with open(sys.argv[2], "rb") as f:
        image = f.read()
    entries, syms = ks.recover(image, None)
    base = next(iter(syms["_text"]))
    want = set(sys.argv[3:])
    for addr, kind, name in entries:
        if name in want:
            print("%016x %s %s" % (addr, kind, name))
    print("# _text = 0x%x" % base)


if __name__ == "__main__":
    main()
