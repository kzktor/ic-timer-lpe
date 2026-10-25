#!/bin/bash
# Quiet run (no IC_ALLOCDBG: the 176 sysfs stat opens allocate dentry/inode/filp
# order-1 slabs right before the spray; usage: run_shield4.sh LOG [EXTRA_CMDLINE_ARGS...]
# Shielded perf peak chain (sparse-push build): anti-fragmentation keeps X's order-1 block at
# <= order 4 by leaving allocator-adjacent slabs alive.  Antifrag left at
# its stock value (ON) unless ic_antifrag=0 is passed.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_perf_paranoid=-1 ic_spray=ioring ic_peasksbf=1 ic_keep_pool=1 ic_perf_events=2048 ic_perf_hold=32 ic_perf_warm=2048 ic_root=1 ic_perf_fixed=1"
timeout 900 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_shield5.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
