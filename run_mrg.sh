#!/bin/bash
# Merge-prevention sweep runner.
# Usage: run_mrg.sh LOG [EXTRA_CMDLINE_ARGS...]
# Initrd carries the window-keep padding code (IC_PAD_SKIP) and its harness
# forwarding.  Defaults here are the AIO order-0 reclaim path, because that is
# the only spray a shell-domain process can create on the device.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
SPRAY=${SPRAY:-aio}
KEEP_POOL=${KEEP_POOL:-1}
SKBF=${SKBF:-1}
INPAGE=${INPAGE:-1}
OPT=""
[ "$KEEP_POOL" = 1 ] && OPT="$OPT ic_keep_pool=1"
[ "$SKBF" = 1 ] && OPT="$OPT ic_peasksbf=1"
[ "$INPAGE" = 1 ] && OPT="$OPT ic_inpage=1"
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1 ic_spray=$SPRAY ic_attempt_wait=600$OPT"
timeout 600 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_mrg.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
