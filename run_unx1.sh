#!/bin/bash
# AF_UNIX SOCK_DGRAM kmalloc-8k reclaim, leak-only.  The spray queues 7808-byte
# datagrams (8128-byte kmalloc-8k data areas, 8K aligned) before B is reaped;
# after release_task runs cleanup_timerqueue through the stale node, the queue
# heads are scanned with MSG_PEEK for the RB_CLEAR_NODE() self-write and the
# attempt parks (a reboot powers the VM off) so the worker bases never tear
# down the datagram that holds X.
# usage: run_unx1.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=unix ic_peasksbf=1 ic_keep_pool=1 ic_root=1 ic_perf_fixed=1 ic_attempt_wait=600 ic_unx_msgs=4096"
timeout 600 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_unx1.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
