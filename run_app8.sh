#!/bin/bash
# Usage: [SMP=6] run_app8.sh LOG EXTRA_CMDLINE_ARGS...
# Phone-faithful app-mode harness.  The physical PD2506 exposes 6 CPUs, so
# fls(6)=3 and SLUB min_objects = 4*(3+1) = 16 -- the same slab geometry as
# the validated 4-CPU harness (8 CPUs would give 20 and change cache orders,
# e.g. kmalloc-512 -> order 2, which broke reclaim in peak_app8_1).
# Boot parameters are the vendor ones read from the 16.1.15.0 vendor_boot
# /chosen node (transparent_hugepage=never, vmalloc=400M, swiotlb=noforce,
# cgroup.memory=nosocket,nokmem, disable_dma32=on).
# Runs as uid/gid 1000 like run_app_base.sh.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
SMP=${SMP:-6}
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp "$SMP" -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
  -initrd initramfs_reap.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
