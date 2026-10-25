import importlib.util
import sys

mod_path, image_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("kallsyms_py", mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
image = open(image_path, "rb").read()
entries, syms = mod.recover(image, None)
with open(out_path, "w") as f:
    for addr, kind, name in entries:
        f.write("%x %s %s\n" % (addr, kind, name))
