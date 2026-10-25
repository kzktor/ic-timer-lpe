#!/bin/bash
# Usage: run_root_aio.sh LOG EXTRA_CMDLINE_ARGS...
# Root-mode QEMU harness with FORWARD pool-free order and no forced spray.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttynull stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr ic_root=1 ic_target=oracle ic_pc=0"
timeout 240 "$QEMU" -M virt -cpu cortex-a72 -smp 4 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
  -initrd initramfs_reap.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
