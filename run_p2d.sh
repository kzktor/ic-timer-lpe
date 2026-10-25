#!/bin/bash
# P2d: reclaim X's merged-proof order-1 block with PERF user pages.
# P2c proved the shields work (vm_area_struct 830->830, filp 725->725,
# dentry 693->693, maple_node 66->66 during a 4096-context AIO spray) but the
# AIO ring pages (GFP_HIGHUSER) never touched the Unmovable buddy lists: u o1
# stayed at 7 blocks while rs fell by 4473 pages.  perf_mmap_alloc_page() uses
# GFP_KERNEL|__GFP_ZERO order-0, which the earlier perf logs show splitting
# u o1..o4.  Keep every other knob identical so only the allocator changes.
# usage: run_p2d.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_spray=perf ic_peasksbf=1 ic_keep_pool=1 ic_root=1 ic_attempt_wait=600 ic_perf_paranoid=-1 ic_perf_events=2048 ic_perf_warm=2048 ic_perf_hold=32 ic_perf_fixed=1 ic_vma_prewarm=16384 ic_vma_keep=10 ic_filp_shield=18000 ic_km64_shield=4096 ic_allocdbg=1 ic_spraydbg=1 ic_ptzone=1 ic_inpage=1"
timeout 900 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_p2c.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
