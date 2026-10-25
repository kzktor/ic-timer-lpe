#!/bin/bash
# Usage: run_ioring_app.sh LOG EXTRA_CMDLINE_ARGS...
# Same as run_ioring.sh but runs the exploit as uid/gid 1000 (no ic_root=1).
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttynull stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr ic_target=oracle ic_spray=ioring ic_pc=0 ic_iorings=512 ic_reverse=1"
timeout 240 "$QEMU" -M virt -cpu cortex-a72 -smp 4 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
  -initrd initramfs_reap.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
