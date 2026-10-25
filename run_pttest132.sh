#!/bin/bash
# Usage: run_pttest132.sh LOG [EXTRA_CMDLINE_ARGS...]
# Boots reap132_pttest.cpio.gz (init.new8 forwards ic_pp_step=,
# exploit.new11 snapshots /proc/pagetypeinfo every N PTE touches).
# Only the PTE probe runs: one order-0 UNMOVABLE page per 2 MB read fault,
# no slab allocations.  Shows which Unmovable orders the vendor allocator
# splits for order-0 requests and where it falls back.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_pageprobe=1 ic_root=1 ic_pp_anon=0 ic_pp_pte=512 ic_pp_step=32 ic_pp_aio_ctxs=0 ic_pp_perf_events=0 ic_pp_pkt_blocks=0 ic_pp_pipes=0 ic_pp_uring_n=0"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_pttest.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
