#!/bin/bash
# Faithful adb-shell run: the harness loads the firmware policy permissively,
# then runs the exploit as uid 2000 in u:r:shell:s0 with enforcement on.
# usage: run_shellboot.sh LOG [EXTRA_CMDLINE_ARGS...]
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_selinux=1 ic_shellboot=1 ic_perf_paranoid=-1 ic_attempt_wait=600"
timeout ${IC_TIMEOUT:-900} "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m ${IC_MEM:-4096} -nographic \
  -no-reboot \
  -kernel ${IC_KERNEL:-/d/kwork/pd2506_161132/kernel_image.bin} \
  -initrd /d/kwork/icbuild/${IC_INITRD:-shellboot_mcast.cpio.gz} \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
