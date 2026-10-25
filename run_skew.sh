#!/bin/bash
# Usage: run_skew.sh LOG EXTRA_CMDLINE_ARGS...
# Boots the offline QEMU harness with the pipe+skb skew test and extra
# ic_* arguments appended to the kernel command line.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttynull stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr ic_root=1 ic_target=oracle ic_spray=pipe ic_pc=0 ic_pipes=1600 ic_pipe_pages=16 ic_skbf=1 ic_skb_socks=64 ic_shrink=1 ic_pt_flush=1"
timeout 240 "$QEMU" -M virt -cpu cortex-a72 -smp 4 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
  -initrd initramfs_reap.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
