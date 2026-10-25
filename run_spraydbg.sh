#!/bin/bash
# Reclaim diagnostics: stop right after the spray (X's stale node is never
# reaped, so no panic) and print the per-cache slab deltas between pad-drop
# (before X's slab is freed) and post-spray (after the ring pages exist).
# usage: run_spraydbg.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=aio ic_peasksbf=1 ic_keep_pool=1 ic_root=1 ic_spray_diag=1 ic_spraydbg=1"
timeout 600 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_spraydbg1.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
