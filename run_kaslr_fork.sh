#!/bin/bash
# Usage: run_kaslr_fork.sh LOG [EXTRA_CMDLINE_ARGS...]
# KASLR harness: NO nokaslr, 8 vCPUs, vendor boot args, app mode (uid 1000),
# fork-path escalation (ic_fork=1). Matches the validated kaslr_fork1 run.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
  -initrd initramfs_reap.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
