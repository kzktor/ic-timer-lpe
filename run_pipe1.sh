#!/bin/bash
# Pipe-only reclaim diagnostic.  Pipes are created before the pool free, so
# the post-flush write(2) burst allocates only order-0 UNMOVABLE data pages
# (no kioctx/inode slab requests ahead of them, unlike io_setup()).  The
# spray is leak-only: pipe pages cannot be modified in place, so the attempt
# parks once the self-referential RB_CLEAR_NODE() write shows up in the read
# back, and the harness powers the VM off.
# usage: run_pipe1.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=pipe ic_peasksbf=1 ic_keep_pool=1 ic_root=1 ic_perf_fixed=1 ic_attempt_wait=600 ic_pipes=1024 ic_pipe_pages=16 ic_filp_shield=18000 ic_km64_shield=1"
timeout 600 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_pipe1.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
