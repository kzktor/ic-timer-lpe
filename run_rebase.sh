#!/bin/bash
# Usage: run_rebase.sh LOG [EXTRA_CMDLINE_ARGS...]
# Regression check: CURRENT timer_lpe.c packed with the ORIGINAL baseline
# harness (init 15:00) and the default flag set of run_kaslr_fork132.sh.
# Ground truth: kaslr_fork132a/l reached [helper] setresuid(0,0,0) ok.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_rebase.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
