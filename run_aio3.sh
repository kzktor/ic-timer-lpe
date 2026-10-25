#!/bin/bash
# AIO reclaim, fault-free variant: every ring page is allocated before any
# mapping is touched (IC_AIO_NOFAULT), so no page-table page can split the
# freshly discarded posix_timers block out from under the spray, and the
# vm_area_struct/maple_node caches are prewarmed (IC_VMA_PREWARM) so do_mmap
# does not ask the buddy for slab pages during the spray either.
# usage: run_aio3.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=aio ic_peasksbf=1 ic_keep_pool=1 ic_perf_events=2048 ic_perf_hold=32 ic_perf_warm=2048 ic_root=1 ic_perf_fixed=1 ic_attempt_wait=600 ic_aio_nofault=1 ic_aio_noremap=1 ic_anon_pages=0 ic_aio_events=1 ic_aio_ctxs=16384 ic_vma_prewarm=16384 ic_vma_keep=10 ic_filp_shield=18000 ic_km64_shield=1"
timeout 900 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_aio3.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
