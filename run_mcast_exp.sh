#!/bin/bash
# Usage: run_kaslr_fork132.sh LOG [EXTRA_CMDLINE_ARGS...]
# 13.2 (PD2506_A_16.1.13.2) kernel image, KASLR on, 8 vCPUs, app mode,
# fork-path escalation. Same harness as run_kaslr_fork.sh but with the
# kernel/initrd extracted from boot_a of the 13.2 device.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1"
timeout 1500 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/icbuild/mcast_exp.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
