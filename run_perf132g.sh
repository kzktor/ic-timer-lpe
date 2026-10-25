#!/bin/bash
# Usage: run_perf132g.sh LOG [EXTRA_CMDLINE_ARGS...]
# Boots reap132_perf_anchor.cpio.gz (exploit.new9: perf spray MAP_FIXED into a
# reserved window whose slots are left unmapped, one anchor vma per 2 MB keeps
# each PTE page alive, so do_mas_munmap() does no maple preallocation before
# rb_alloc()'s user page).
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_perf_anchor.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
