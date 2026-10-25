# init_scan.py -- report which shellboot init variant each cpio carries.
# Read-only: prints one line per archive; args are archive paths.
import gzip
import sys


def read_archive(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    out = []
    pos = 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] != b"070701":
            raise SystemExit("bad magic in %s at %d" % (path, pos))
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16)
                  for i in range(13)]
        size, namesz = fields[6], fields[11]
        name_start = pos + 110
        name = data[name_start:name_start + namesz].rstrip(b"\0").decode(
            "utf-8", "replace")
        body_start = (name_start + namesz + 3) & ~3
        body = data[body_start:body_start + size]
        pos = (body_start + size + 3) & ~3
        if name == "TRAILER!!!":
            break
        out.append((name.lstrip("/"), body))
    return dict(out)


MARKERS = (
    b"/dev/ic-out",
    b"ic-work/log",
    b"adb_data_file",
    b"shell_data_file",
    b"from /tmp/ic-shell-boot",
    b"from /proc/self/exe",
    b"ic_shellboot_spray",
    b"ic_skb_socks",
    b"ic_scan_ctxmap",
)


def main():
    for path in sys.argv[1:]:
        try:
            entries = read_archive(path)
        except SystemExit as e:
            print("%-34s ERROR %s" % (path.split("/")[-1], e))
            continue
        init = entries.get("init", b"")
        exp = entries.get("exploit", b"")
        hits = ",".join(m.decode() for m in MARKERS if m in init)
        print("%-34s init=%7d exploit=%7d %s"
              % (path.split("/")[-1], len(init), len(exp), hits))


main()
