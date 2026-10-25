#!/bin/bash
# P2c: fault-free AIO reclaim with the merge-proof VMA/maple prewarm.
# The prewarm now alternates PROT_NONE/PROT_READ so do_mmap() cannot merge the
# mappings; every slab keeps >=1 object at any keep >= 2, so no slab is ever
# discarded and the prewarm frees no order-0 page.  Spray size is reduced to
# 4096 because X's block is split by the first pcp refill (the first ~63
# order-0 allocations), so thousands of extra contexts only add stealers.
# usage: run_p2c.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=aio ic_peasksbf=1 ic_keep_pool=1 ic_root=1 ic_attempt_wait=600 ic_aio_nofault=1 ic_aio_noremap=1 ic_anon_pages=0 ic_aio_events=1 ic_aio_ctxs=4096 ic_vma_prewarm=16384 ic_vma_keep=10 ic_filp_shield=18000 ic_km64_shield=1 ic_allocdbg=1 ic_spraydbg=1 ic_ptzone=1 ic_inpage=1 ic_aio_probe=1"
timeout 900 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_p2c.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
